import BoundCurl
import ArmorCore
import Foundation
import Network
import Security

public struct TunnelCheckResult: Sendable {
    public let first: EgressObservation
    public let second: EgressObservation
    public let tunnel: VerifiedTunnel
}

public enum TunnelEgressChecker {
    public static func check(ownerKey: String?, probeAddresses: [String: String] = [:],
                             verifier: EgressVerifier? = nil,
                             independentExit: Bool = false) async throws -> TunnelCheckResult {
        let worker = Task.detached(priority: .utility) { try TunnelOwnershipReader.select(TunnelOwnershipReader.read(), ownerKey: ownerKey) }
        let tunnel = try await withTaskCancellationHandler(operation: { try await worker.value }, onCancel: { worker.cancel() })
        let service: EgressVerifier
        if let verifier { service = verifier } else { service = await EgressVerifier.shared }
        // A firewall's explicit probe allowlist is never expanded by fallback.
        let result = try await service.check(primary: .ipWhoIS, allowsBackup: probeAddresses.isEmpty,
                                             mode: independentExit ? .independentExit : .addressLookup) { provider, observedIP in
            let url = try provider.lookupURL(address: observedIP)
            if independentExit, probeAddresses.isEmpty {
                let body = try await BoundTunnelProbe.get(url: url, interface: tunnel.interface)
                return try EgressObservation.decode(body, provider: provider)
            }
            let path = url.path + (url.query.map { "?" + $0 } ?? "")
            let body = try await TunnelHTTP.get(host: provider.host, path: path, interface: tunnel.interface,
                                                 address: probeAddresses[provider.host])
            return try EgressObservation.decode(body, provider: provider)
        }
        let verification = Task.detached(priority: .utility) {
            try TunnelOwnershipReader.select(TunnelOwnershipReader.read(), ownerKey: tunnel.ownerKey)
        }
        let after = try await withTaskCancellationHandler(operation: { try await verification.value }, onCancel: { verification.cancel() })
        guard after == tunnel else { throw TunnelCheckError.changed }
        return TunnelCheckResult(first: result.first, second: result.second, tunnel: tunnel)
    }
}

// Unlike NWPath.availableInterfaces, an explicit IPv4 socket binding also
// works for utun devices that are absent from the default network path.
enum BoundTunnelProbe {
    static func get(url: URL, interface: String) async throws -> Data {
        let work = Task.detached(priority: .utility) {
            try Task.checkCancellation()
            var body = [UInt8](repeating: 0, count: 4096)
            var length = 0, status = 0, retry = 0
            let result = ra_tunnel_get(url.absoluteString, interface, &body, 4096, &length, &status, &retry) {
                Task.isCancelled ? 1 : 0
            }
            try Task.checkCancellation()
            if status >= 300 {
                throw EgressError.httpFailure(status: status, retryAfter: retry > 0 ? String(retry) : nil)
            }
            switch result {
            case RA_OK:
                guard status == 200 else { throw EgressError.invalidResponse }
                return Data(body.prefix(length))
            case RA_BIND: throw URLError(.notConnectedToInternet)
            case RA_TIMEOUT: throw URLError(.timedOut)
            case RA_DNS: throw URLError(.cannotFindHost)
            case RA_TLS: throw URLError(.secureConnectionFailed)
            case RA_TOO_LARGE: throw EgressError.responseTooLarge
            case RA_CANCELLED: throw CancellationError()
            default: throw URLError(.cannotConnectToHost)
            }
        }
        return try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
    }
}

/// Small, bounded HTTP/1.1-over-TLS client. No redirects, cookies, proxy discovery,
/// credentials, TLS overrides or fallback to an unrestricted URLSession.
public final class TunnelHTTP: @unchecked Sendable {
    private let queue = DispatchQueue(label: "app.russian-armor.tunnel-http")
    private var monitor: NWPathMonitor?
    private var connection: NWConnection?
    private var continuation: CheckedContinuation<Data, Error>?
    private var buffer = Data()
    private var finished = false

    public static func get(host: String, path: String, interface: String, address: String? = nil) async throws -> Data {
        let request = TunnelHTTP()
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                request.queue.async { request.start(host: host, path: path, interface: interface, address: address, continuation: continuation) }
            }
        }, onCancel: {
            request.queue.async { request.finish(.failure(CancellationError())) }
        })
    }

    private func start(host: String, path: String, interface: String, address: String?, continuation: CheckedContinuation<Data, Error>) {
        if finished { continuation.resume(throwing: CancellationError()); return }
        self.continuation = continuation
        let monitor = NWPathMonitor()
        self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] pathStatus in
            guard let self, !self.finished, self.connection == nil else { return }
            guard let required = pathStatus.availableInterfaces.first(where: { $0.name == interface }) else {
                self.finish(.failure(TunnelCheckError.unavailable)); return
            }
            self.monitor?.cancel()
            self.monitor = nil
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
            sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
            sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
            let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
            parameters.requiredInterface = required
            guard let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options else {
                self.finish(.failure(TunnelCheckError.unavailable)); return
            }
            ip.version = .v4
            let connection = NWConnection(host: NWEndpoint.Host(address ?? host), port: 443, using: parameters)
            self.connection = connection
            connection.stateUpdateHandler = { [weak self] state in
                guard let self, !self.finished else { return }
                switch state {
                case .ready:
                    let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
                    connection.send(content: Data(request.utf8), completion: .contentProcessed { [weak self] error in
                        if let error { self?.finish(.failure(error)) } else { self?.receive() }
                    })
                case .failed(let error), .waiting(let error): self.finish(.failure(error))
                case .cancelled: self.finish(.failure(CancellationError()))
                default: break
                }
            }
            connection.start(queue: self.queue)
        }
        monitor.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 8) { [weak self] in self?.finish(.failure(URLError(.timedOut))) }
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, complete, error in
            guard let self, !self.finished else { return }
            if let data { self.buffer.append(data) }
            do {
                guard self.buffer.count <= 32_768 else { throw EgressError.responseTooLarge }
                if let body = try TunnelHTTPResponse.body(self.buffer, complete: complete) {
                    self.finish(.success(body))
                } else if let error {
                    self.finish(.failure(error))
                } else {
                    self.receive()
                }
            } catch { self.finish(.failure(error)) }
        }
    }

    private func finish(_ result: Result<Data, Error>) {
        guard !finished else { return }
        finished = true
        monitor?.cancel(); monitor = nil
        connection?.stateUpdateHandler = nil
        connection?.cancel(); connection = nil
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(with: result)
    }
}

enum TunnelHTTPResponse {
    static func body(_ data: Data, complete: Bool) throws -> Data? {
        guard let boundary = data.range(of: Data("\r\n\r\n".utf8)) else {
            if complete || data.count > 8192 { throw TunnelCheckError.invalidHTTP }
            return nil
        }
        guard boundary.lowerBound <= 8192,
              let text = String(data: data[..<boundary.lowerBound], encoding: .utf8) else { throw TunnelCheckError.invalidHTTP }
        let lines = text.components(separatedBy: "\r\n")
        let status = lines[0].split(separator: " ")
        guard status.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(status[0])), let code = Int(status[1]) else {
            throw TunnelCheckError.invalidHTTP
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("\t") else { throw TunnelCheckError.invalidHTTP }
            let name = line[..<colon].lowercased()
            guard headers[name] == nil else { throw TunnelCheckError.invalidHTTP }
            headers[name] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard code == 200 else {
            throw EgressError.httpFailure(status: code, retryAfter: headers["retry-after"])
        }
        if let encoding = headers["content-encoding"], encoding.lowercased() != "identity" { throw TunnelCheckError.invalidHTTP }
        let payload = Data(data[boundary.upperBound...])
        if let transfer = headers["transfer-encoding"] {
            guard transfer.lowercased() == "chunked", headers["content-length"] == nil else { throw TunnelCheckError.invalidHTTP }
            return try chunks(payload, complete: complete)
        }
        if let text = headers["content-length"] {
            guard !text.isEmpty, text.allSatisfy({ $0.isASCII && $0.isNumber }), let length = Int(text), length <= 4096 else {
                throw EgressError.responseTooLarge
            }
            guard payload.count >= length else {
                if complete { throw TunnelCheckError.invalidHTTP }
                return nil
            }
            guard payload.count == length else { throw TunnelCheckError.invalidHTTP }
            return payload
        }
        guard payload.count <= 4096 else { throw EgressError.responseTooLarge }
        return complete ? payload : nil
    }

    private static func chunks(_ data: Data, complete: Bool) throws -> Data? {
        var cursor = 0
        var result = Data()
        let bytes = Array(data)
        func incomplete() throws -> Data? {
            if complete { throw TunnelCheckError.invalidHTTP }
            return nil
        }
        while cursor < bytes.count {
            guard let end = (cursor..<max(cursor, bytes.count - 1)).first(where: { bytes[$0] == 13 && bytes[$0 + 1] == 10 }) else { return try incomplete() }
            let line = String(decoding: bytes[cursor..<end], as: UTF8.self)
            guard let sizePart = line.split(separator: ";", maxSplits: 1).first else { throw TunnelCheckError.invalidHTTP }
            let sizeText = String(sizePart)
            guard !sizeText.isEmpty, sizeText.count <= 8,
                  sizeText.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
                  let size = Int(sizeText, radix: 16) else { throw TunnelCheckError.invalidHTTP }
            cursor = end + 2
            guard size <= 4096 - result.count else { throw EgressError.responseTooLarge }
            guard bytes.count - cursor >= size + 2 else { return try incomplete() }
            if size == 0 {
                // No trailers are requested; reject them rather than ambiguously parse.
                guard bytes.count == cursor + 2, bytes[cursor] == 13, bytes[cursor + 1] == 10 else { throw TunnelCheckError.invalidHTTP }
                return result
            }
            result.append(contentsOf: bytes[cursor..<(cursor + size)])
            cursor += size
            guard bytes[cursor] == 13, bytes[cursor + 1] == 10 else { throw TunnelCheckError.invalidHTTP }
            cursor += 2
        }
        return try incomplete()
    }
}
