import ArmourCore
import Foundation
import LocalAuthentication
import Network
import NetworkExtension
import Security

/// Only the router address is opened by this process. Destination names remain
/// inside the authenticated, certificate-pinned router connection.
struct RouterTransportConfiguration {
    let address: IPv4Address
    let port: Network.NWEndpoint.Port
    let username: String
    let password: String
    let certificateSHA256: Data
    let tlsServerName: String
    let configurationID: String

    init(protocolConfiguration: NEVPNProtocol) throws {
        guard let tunnel = protocolConfiguration as? NETunnelProviderProtocol,
              let values = tunnel.providerConfiguration,
              let host = values["host"] as? String,
              let address = IPv4Address(host),
              Self.isPrivate(address),
              let number = values["port"] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue == Double(number.intValue),
              (1...65_535).contains(number.intValue),
              let port = Network.NWEndpoint.Port(rawValue: number.uint16Value),
              let username = values["username"] as? String,
              let reference = tunnel.passwordReference,
              let pinText = values["routerCertificateSHA256"] as? String,
              let pin = Self.decodePin(pinText),
              let generation = values["configurationID"] as? String,
              UUID(uuidString: generation) != nil,
              let name = values["tlsServerName"] as? String,
              name == "russian-armour.router",
              let accessGroup = Bundle.main.object(forInfoDictionaryKey: "ArmourKeychainAccessGroup") as? String,
              !accessGroup.isEmpty else { throw RouterProxyError.invalidConfiguration }

        let authentication = LAContext()
        authentication.interactionNotAllowed = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecValuePersistentRef: reference,
            kSecAttrAccessGroup: accessGroup,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authentication,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as CFDictionary, &result)
        guard status == errSecSuccess,
              let bytes = result as? Data,
              let password = String(data: bytes, encoding: .utf8) else {
            throw RouterProxyError.credentialUnavailable
        }
        // Validate lengths before any connection is attempted. Do not retain
        // serialized authentication bytes in preferences or diagnostics.
        _ = try SOCKS5Codec.authenticationRequest(username: username, password: password)
        self.address = address
        self.port = port
        self.username = username
        self.password = password
        self.certificateSHA256 = pin
        self.tlsServerName = name
        self.configurationID = generation
    }

    private static func isPrivate(_ address: IPv4Address) -> Bool {
        let bytes = [UInt8](address.rawValue)
        return bytes.count == 4 && (bytes[0] == 10
            || (bytes[0] == 172 && (16...31).contains(bytes[1]))
            || (bytes[0] == 192 && bytes[1] == 168))
    }

    private static func decodePin(_ text: String) -> Data? {
        guard text.utf8.count == 64 else { return nil }
        var result = Data()
        var index = text.startIndex
        for _ in 0..<32 {
            let end = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<end], radix: 16) else { return nil }
            result.append(byte)
            index = end
        }
        return result
    }
}

enum RouterProxyError: Error {
    case invalidConfiguration, credentialUnavailable, refused, timedOut, closed, malformedReply

    var flowError: NSError {
        let code: NEAppProxyFlowError.Code
        switch self {
        case .timedOut: code = .timedOut
        case .refused: code = .refused
        default: code = .aborted
        }
        // These errors intentionally contain no destination or credential data.
        return NSError(domain: NEAppProxyErrorDomain, code: code.rawValue)
    }
}

protocol AuthenticatedRouterTransport: AnyObject {
    var onFailure: ((Error) -> Void)? { get set }
    func start(completion: @escaping (Error?) -> Void)
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func finishSending(completion: @escaping (Error?) -> Void)
    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}

protocol DNSRouterTransport: AuthenticatedRouterTransport {
    func receiveExactly(_ count: Int, completion: @escaping (Data?, Error?) -> Void)
}

/// Queue-confined SOCKS connection. All operations (including cancellation) are
/// serialized by the provider's queue. No code path opens the destination itself.
final class RouterSOCKSConnection: DNSRouterTransport {
    private enum Stage { case connecting, method, authentication, connect, ready, closed }
    private let queue: DispatchQueue
    private let configuration: RouterTransportConfiguration
    private let destinationHost: String
    private let destinationPort: UInt16
    private let connection: NWConnection
    private var stage = Stage.connecting
    private var handshakeBuffer = Data()
    private var bufferedPayload = Data()
    private var deadline: DispatchWorkItem?
    private var completion: ((Error?) -> Void)?
    var onFailure: ((Error) -> Void)?

    init(configuration: RouterTransportConfiguration, host: String, port: UInt16, queue: DispatchQueue) throws {
        // Fail before opening a socket for invalid destinations.
        _ = try SOCKS5Codec.connectRequest(host: host, port: port)
        self.configuration = configuration
        destinationHost = host
        destinationPort = port
        self.queue = queue

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, configuration.tlsServerName)
        let expectedPin = configuration.certificateSHA256
        let expectedName = configuration.tlsServerName
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, verifyComplete in
            let object = sec_trust_copy_ref(trust).takeRetainedValue()
            verifyComplete(RouterTLSVerifier.validate(object, certificateSHA256: expectedPin,
                                                      serverName: expectedName))
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.allowLocalEndpointReuse = false
        connection = NWConnection(host: .ipv4(configuration.address), port: configuration.port, using: parameters)
    }

    func start(completion: @escaping (Error?) -> Void) {
        self.completion = completion
        let timeout = DispatchWorkItem { [weak self] in self?.fail(RouterProxyError.timedOut) }
        deadline = timeout
        queue.asyncAfter(deadline: .now() + 15, execute: timeout)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, self.stage != .closed else { return }
            switch state {
            case .ready:
                guard self.stage == .connecting else { return }
                self.stage = .method
                self.sendHandshake(SOCKS5Codec.methodGreeting)
            case .failed(let error): self.fail(error)
            case .cancelled: self.fail(RouterProxyError.closed)
            case .waiting:
                if self.stage == .ready { self.fail(RouterProxyError.closed) }
            default: break
            }
        }
        connection.viabilityUpdateHandler = { [weak self] viable in
            guard let self, !viable, self.stage == .ready else { return }
            self.fail(RouterProxyError.closed)
        }
        connection.start(queue: queue)
    }

    private func sendHandshake(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self, self.stage != .closed else { return }
            if let error { self.fail(error) } else { self.readHandshake() }
        })
    }

    private func readHandshake() {
        guard stage != .closed else { return }
        do {
            let reply: SOCKS5Reply?
            switch stage {
            case .method: reply = try SOCKS5Codec.parseMethodSelection(handshakeBuffer)
            case .authentication: reply = try SOCKS5Codec.parseAuthenticationReply(handshakeBuffer)
            case .connect: reply = try SOCKS5Codec.parseConnectReply(handshakeBuffer)
            default: throw RouterProxyError.malformedReply
            }
            if let reply {
                handshakeBuffer = reply.remainder
                switch stage {
                case .method:
                    stage = .authentication
                    sendHandshake(try SOCKS5Codec.authenticationRequest(
                        username: configuration.username, password: configuration.password))
                case .authentication:
                    stage = .connect
                    sendHandshake(try SOCKS5Codec.connectRequest(host: destinationHost, port: destinationPort))
                case .connect:
                    bufferedPayload = handshakeBuffer
                    handshakeBuffer.removeAll(keepingCapacity: false)
                    stage = .ready
                    deadline?.cancel()
                    deadline = nil
                    let callback = completion
                    completion = nil
                    callback?(nil)
                default: break
                }
                return
            }
            guard handshakeBuffer.count <= SOCKS5Codec.maximumConnectReplyLength else {
                throw RouterProxyError.malformedReply
            }
            connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { [weak self] data, _, isComplete, error in
                guard let self, self.stage != .closed else { return }
                if let error { self.fail(error); return }
                guard let data, !data.isEmpty, !isComplete else { self.fail(RouterProxyError.closed); return }
                self.handshakeBuffer.append(data)
                self.readHandshake()
            }
        } catch { fail(error) }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard stage == .ready else { completion(RouterProxyError.closed); return }
        connection.send(content: data, completion: .contentProcessed(completion))
    }

    func finishSending(completion: @escaping (Error?) -> Void) {
        guard stage == .ready else { completion(RouterProxyError.closed); return }
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed(completion))
    }

    func receive(maximumLength: Int = 65_536, completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard stage == .ready else { completion(nil, true, RouterProxyError.closed); return }
        if !bufferedPayload.isEmpty {
            let count = min(maximumLength, bufferedPayload.count)
            let data = Data(bufferedPayload.prefix(count))
            bufferedPayload.removeFirst(count)
            completion(data, false, nil)
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximumLength) { data, _, complete, error in
            completion(data, complete, error)
        }
    }

    func receiveExactly(_ count: Int, completion: @escaping (Data?, Error?) -> Void) {
        guard count > 0, count <= 65_535 else { completion(nil, RouterProxyError.malformedReply); return }
        receiveExactly(count, accumulated: Data(), completion: completion)
    }

    private func receiveExactly(_ remaining: Int, accumulated: Data, completion: @escaping (Data?, Error?) -> Void) {
        receive(maximumLength: remaining) { [weak self] bytes, finished, error in
            guard let self else { return }
            if let error { completion(nil, error); return }
            var result = accumulated
            if let bytes { result.append(bytes) }
            if result.count == accumulated.count + remaining {
                completion(result, nil)
            } else if finished || bytes?.isEmpty != false {
                completion(nil, RouterProxyError.closed)
            } else {
                self.receiveExactly(remaining - (bytes?.count ?? 0), accumulated: result, completion: completion)
            }
        }
    }

    private func fail(_ error: Error) {
        guard stage != .closed else { return }
        let callback = completion
        completion = nil
        cancel()
        if let callback { callback(error) } else { onFailure?(error) }
    }

    func cancel() {
        guard stage != .closed else { return }
        stage = .closed
        deadline?.cancel()
        deadline = nil
        completion = nil
        bufferedPayload.removeAll(keepingCapacity: false)
        handshakeBuffer.removeAll(keepingCapacity: false)
        connection.stateUpdateHandler = nil
        connection.viabilityUpdateHandler = nil
        connection.cancel()
    }

    deinit { deadline?.cancel() }
}
