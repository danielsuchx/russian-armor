import Foundation
import Network
import NetworkExtension

protocol ProxyFlowRelay: AnyObject {
    func start()
    func cancel()
}

/// A normal per-app proxy is intentional: declining a flow terminates it.
/// NETransparentProxyProvider has different (direct-bypass) return semantics.
final class ArmourProxyProvider: NEAppProxyProvider {
    private let workQueue = DispatchQueue(label: "app.russian-armour.proxy", qos: .userInitiated)
    private let queueKey = DispatchSpecificKey<UInt8>()
    private var configuration: RouterTransportConfiguration?
    private var relays: [UUID: ProxyFlowRelay] = [:]
    private var sleeping = false
    private var monitor: NWPathMonitor?
    private var lastPath: String?
    private var lifecycle = UUID()
    private static let maximumFlows = 256

    override init() {
        super.init()
        workQueue.setSpecific(key: queueKey, value: 1)
    }

    private func serialized<T>(_ operation: () -> T) -> T {
        if DispatchQueue.getSpecific(key: queueKey) != nil { return operation() }
        return workQueue.sync(execute: operation)
    }

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        workQueue.async { [weak self] in
            guard let self else { completionHandler(RouterProxyError.closed.flowError); return }
            let generation = UUID()
            self.lifecycle = generation
            self.configuration = nil
            self.monitor?.cancel()
            self.monitor = nil
            self.cancelRelays()
            do {
                let configuration = try RouterTransportConfiguration(protocolConfiguration: self.protocolConfiguration)
                self.configuration = configuration
                self.sleeping = false
                let settings = NETunnelNetworkSettings(tunnelRemoteAddress: configuration.address.debugDescription)
                let dns = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
                dns.matchDomains = [""]
                dns.matchDomainsNoSearch = true
                settings.dnsSettings = dns
                self.setTunnelNetworkSettings(settings) { [weak self] error in
                    guard let self else { completionHandler(RouterProxyError.closed.flowError); return }
                    self.workQueue.async {
                        guard self.lifecycle == generation else {
                            completionHandler(RouterProxyError.closed.flowError)
                            return
                        }
                        if error != nil {
                            self.configuration = nil
                            completionHandler(RouterProxyError.invalidConfiguration.flowError)
                        } else {
                            self.startPathMonitor()
                            // Router availability is deliberately NOT a start condition.
                            // An unavailable router denies flows while the per-app rules
                            // stay installed, rather than disconnecting the guard.
                            completionHandler(nil)
                        }
                    }
                }
            } catch {
                self.configuration = nil
                completionHandler(RouterProxyError.invalidConfiguration.flowError)
            }
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        workQueue.async { [weak self] in
            self?.lifecycle = UUID()
            self?.configuration = nil
            self?.monitor?.cancel()
            self?.monitor = nil
            self?.cancelRelays()
            completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        serialized {
            guard let configuration, !sleeping, relays.count < Self.maximumFlows else {
                reject(flow)
                return false
            }
            let id = UUID()
            let finished: () -> Void = { [weak self] in self?.relays.removeValue(forKey: id) }
            let relay: ProxyFlowRelay
            if let tcp = flow as? NEAppProxyTCPFlow {
                guard let endpoint = tcp.remoteEndpoint as? NWHostEndpoint,
                      let port = UInt16(endpoint.port), port != 0 else {
                    reject(flow)
                    return false
                }
                do {
                    relay = try TCPFlowRelay(flow: tcp, configuration: configuration,
                                             host: tcp.remoteHostname ?? endpoint.hostname,
                                             port: port, queue: workQueue, onFinish: finished)
                } catch {
                    reject(flow)
                    return false
                }
            } else if let udp = flow as? NEAppProxyUDPFlow {
                // DNS is framed over authenticated SOCKS TCP. No UDP socket is
                // ever opened by the provider; other datagrams are refused.
                relay = DNSFlowRelay(flow: udp, configuration: configuration,
                                     queue: workQueue, onFinish: finished)
            } else {
                reject(flow)
                return false
            }
            relays[id] = relay
            relay.start()
            return true
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        workQueue.async { [weak self] in
            guard let self,
                  messageData.count <= 256,
                  let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                  request["version"] as? Int == 1,
                  request["command"] as? String == "status" else {
                completionHandler?(nil)
                return
            }
            // 'ready' is a provider/configuration heartbeat, not a claim that
            // the router is reachable or that old sockets have been intercepted.
            let response: [String: Any] = ["version": 1,
                                           "ready": self.configuration != nil && !self.sleeping,
                                           "configurationID": self.configuration?.configurationID ?? "",
                                           "transport": "tls-pinned-socks5",
                                           "activeFlows": self.relays.count]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        workQueue.async { [weak self] in
            self?.sleeping = true
            self?.cancelRelays()
            completionHandler()
        }
    }

    override func wake() {
        workQueue.async { [weak self] in self?.sleeping = false }
    }

    private func reject(_ flow: NEAppProxyFlow) {
        let error = RouterProxyError.refused.flowError
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }

    private func cancelRelays() {
        let values = Array(relays.values)
        relays.removeAll()
        values.forEach { $0.cancel() }
    }

    private func startPathMonitor() {
        monitor?.cancel()
        lastPath = nil
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let fingerprint = "\(path.status)|" + path.availableInterfaces
                .map { "\($0.index):\($0.name)" }.sorted().joined(separator: ",")
            if path.status != .satisfied || (self.lastPath != nil && self.lastPath != fingerprint) {
                self.cancelRelays()
            }
            self.lastPath = fingerprint
        }
        self.monitor = monitor
        monitor.start(queue: workQueue)
    }
}

protocol TCPProxySourceFlow: AnyObject {
    func open(completion: @escaping (Error?) -> Void)
    func read(completion: @escaping (Data?, Error?) -> Void)
    func write(_ data: Data, completion: @escaping (Error?) -> Void)
    func closeRead(_ error: NSError?)
    func closeWrite(_ error: NSError?)
}

private final class SystemTCPProxySourceFlow: TCPProxySourceFlow {
    private let flow: NEAppProxyTCPFlow
    init(_ flow: NEAppProxyTCPFlow) { self.flow = flow }
    func open(completion: @escaping (Error?) -> Void) { flow.open(withLocalEndpoint: nil, completionHandler: completion) }
    func read(completion: @escaping (Data?, Error?) -> Void) { flow.readData(completionHandler: completion) }
    func write(_ data: Data, completion: @escaping (Error?) -> Void) { flow.write(data, withCompletionHandler: completion) }
    func closeRead(_ error: NSError?) { flow.closeReadWithError(error) }
    func closeWrite(_ error: NSError?) { flow.closeWriteWithError(error) }
}

final class TCPFlowRelay: ProxyFlowRelay {
    private let flow: TCPProxySourceFlow
    private let transport: AuthenticatedRouterTransport
    private let queue: DispatchQueue
    private let onFinish: () -> Void
    private var closed = false
    private var appFinished = false
    private var remoteFinished = false

    init(flow: NEAppProxyTCPFlow, configuration: RouterTransportConfiguration, host: String,
         port: UInt16, queue: DispatchQueue, onFinish: @escaping () -> Void) throws {
        self.flow = SystemTCPProxySourceFlow(flow)
        self.queue = queue
        self.onFinish = onFinish
        transport = try RouterSOCKSConnection(configuration: configuration, host: host, port: port, queue: queue)
    }

    init(flow: TCPProxySourceFlow, transport: AuthenticatedRouterTransport,
         queue: DispatchQueue, onFinish: @escaping () -> Void) {
        self.flow = flow
        self.transport = transport
        self.queue = queue
        self.onFinish = onFinish
    }

    func start() {
        transport.onFailure = { [weak self] error in self?.finish(error) }
        transport.start { [weak self] error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error); return }
            self.flow.open { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    guard !self.closed else { return }
                    if let error { self.finish(error); return }
                    self.readApplication()
                    self.readRemote()
                }
            }
        }
    }

    private func readApplication() {
        guard !closed, !appFinished else { return }
        flow.read { [weak self] data, error in
            guard let self else { return }
            self.queue.async {
                guard !self.closed else { return }
                if let error { self.finish(error); return }
                guard let data else { self.finish(RouterProxyError.closed); return }
                if data.isEmpty {
                    self.appFinished = true
                    self.flow.closeRead(nil)
                    self.transport.finishSending { [weak self] error in
                        guard let self, !self.closed else { return }
                        if let error { self.finish(error) }
                        else if self.remoteFinished { self.finish(nil) }
                    }
                    return
                }
                guard data.count <= 1_048_576 else { self.finish(RouterProxyError.refused); return }
                // Exactly one app read is in flight. The next read is scheduled
                // only after the network stack has accepted the previous write.
                self.transport.send(data) { [weak self] error in
                    guard let self, !self.closed else { return }
                    if let error { self.finish(error) } else { self.readApplication() }
                }
            }
        }
    }

    private func readRemote() {
        guard !closed, !remoteFinished else { return }
        transport.receive(maximumLength: 65_536) { [weak self] data, complete, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error); return }
            let advance: () -> Void = { [weak self] in
                guard let self, !self.closed else { return }
                if complete {
                    self.remoteFinished = true
                    self.flow.closeWrite(nil)
                    if self.appFinished { self.finish(nil) }
                } else { self.readRemote() }
            }
            if let data, !data.isEmpty {
                self.flow.write(data) { [weak self] error in
                    guard let self else { return }
                    self.queue.async {
                        guard !self.closed else { return }
                        if let error { self.finish(error) } else { advance() }
                    }
                }
            } else if complete {
                advance()
            } else {
                self.finish(RouterProxyError.closed)
            }
        }
    }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true
        transport.cancel()
        let reported = error == nil ? nil : RouterProxyError.closed.flowError
        flow.closeRead(reported)
        flow.closeWrite(reported)
        onFinish()
    }

    func cancel() { finish(RouterProxyError.closed) }
}

/// A DNS UDP flow is served using one bounded DNS-over-TCP exchange at a time.
/// This prevents the resolver from bypassing the protected router path.
protocol DNSProxySourceFlow: AnyObject {
    func open(completion: @escaping (Error?) -> Void)
    func readDatagrams(completion: @escaping ([Data]?, [NWHostEndpoint]?, Error?) -> Void)
    func writeDatagrams(_ datagrams: [Data], sentBy endpoints: [NWHostEndpoint], completion: @escaping (Error?) -> Void)
    func closeRead(_ error: NSError?)
    func closeWrite(_ error: NSError?)
}

private final class SystemDNSProxySourceFlow: DNSProxySourceFlow {
    private let flow: NEAppProxyUDPFlow
    init(_ flow: NEAppProxyUDPFlow) { self.flow = flow }
    func open(completion: @escaping (Error?) -> Void) { flow.open(withLocalEndpoint: nil, completionHandler: completion) }
    func readDatagrams(completion: @escaping ([Data]?, [NWHostEndpoint]?, Error?) -> Void) {
        flow.readDatagrams { datagrams, endpoints, error in
            guard error == nil, let endpoints else { completion(datagrams, nil, error); return }
            let hosts = endpoints.compactMap { $0 as? NWHostEndpoint }
            guard hosts.count == endpoints.count else { completion(nil, nil, RouterProxyError.refused); return }
            completion(datagrams, hosts, nil)
        }
    }
    func writeDatagrams(_ datagrams: [Data], sentBy endpoints: [NWHostEndpoint], completion: @escaping (Error?) -> Void) {
        flow.writeDatagrams(datagrams, sentBy: endpoints, completionHandler: completion)
    }
    func closeRead(_ error: NSError?) { flow.closeReadWithError(error) }
    func closeWrite(_ error: NSError?) { flow.closeWriteWithError(error) }
}

final class DNSFlowRelay: ProxyFlowRelay {
    private struct Query {
        let bytes: Data
        let endpoint: NWHostEndpoint
    }
    private let flow: DNSProxySourceFlow
    private let makeTransport: (String) throws -> DNSRouterTransport
    private let queue: DispatchQueue
    private let onFinish: () -> Void
    private var closed = false
    private var pending: [Query] = []
    private var transport: DNSRouterTransport?
    private var deadline: DispatchWorkItem?

    init(flow: NEAppProxyUDPFlow, configuration: RouterTransportConfiguration,
         queue: DispatchQueue, onFinish: @escaping () -> Void) {
        self.flow = SystemDNSProxySourceFlow(flow)
        self.makeTransport = { host in
            try RouterSOCKSConnection(configuration: configuration, host: host, port: 53, queue: queue)
        }
        self.queue = queue
        self.onFinish = onFinish
    }

    init(flow: DNSProxySourceFlow, queue: DispatchQueue,
         makeTransport: @escaping (String) throws -> DNSRouterTransport, onFinish: @escaping () -> Void) {
        self.flow = flow
        self.makeTransport = makeTransport
        self.queue = queue
        self.onFinish = onFinish
    }

    func start() {
        flow.open { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard !self.closed else { return }
                if let error { self.finish(error) } else { self.readQueries() }
            }
        }
    }

    private func readQueries() {
        guard !closed else { return }
        // Idle DNS sockets must not occupy the bounded provider capacity forever.
        armDeadline(seconds: 60)
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self else { return }
            self.queue.async {
                guard !self.closed else { return }
                self.deadline?.cancel()
                if let error { self.finish(error); return }
                guard let datagrams, let endpoints,
                      datagrams.count == endpoints.count,
                      !datagrams.isEmpty, datagrams.count <= 16 else {
                    self.finish(RouterProxyError.refused)
                    return
                }
                var queries: [Query] = []
                for (bytes, endpoint) in zip(datagrams, endpoints) {
                    let host = endpoint
                    guard UInt16(host.port) == 53,
                          (12...4096).contains(bytes.count),
                          bytes[bytes.startIndex + 2] & 0x80 == 0 else {
                        self.finish(RouterProxyError.refused)
                        return
                    }
                    queries.append(Query(bytes: bytes, endpoint: host))
                }
                self.pending = queries
                self.processNextQuery()
            }
        }
    }

    private func processNextQuery() {
        guard !closed else { return }
        guard !pending.isEmpty else { readQueries(); return }
        let query = pending.removeFirst()
        do {
            let connection = try makeTransport(query.endpoint.hostname)
            transport = connection
            connection.onFailure = { [weak self] error in self?.finish(error) }
            armDeadline(seconds: 20)
            connection.start { [weak self, weak connection] error in
                guard let self, let connection, !self.closed else { return }
                if let error { self.finish(error); return }
                let length = UInt16(query.bytes.count)
                var framed = Data([UInt8(length >> 8), UInt8(length & 0xff)])
                framed.append(query.bytes)
                connection.send(framed) { [weak self, weak connection] error in
                    guard let self, let connection, !self.closed else { return }
                    if let error { self.finish(error); return }
                    connection.receiveExactly(2) { [weak self, weak connection] prefix, error in
                        guard let self, let connection, !self.closed else { return }
                        guard error == nil, let prefix, prefix.count == 2 else {
                            self.finish(error ?? RouterProxyError.malformedReply); return
                        }
                        let length = Int(prefix[prefix.startIndex]) << 8 | Int(prefix[prefix.startIndex + 1])
                        guard length >= 12 else { self.finish(RouterProxyError.malformedReply); return }
                        connection.receiveExactly(length) { [weak self, weak connection] answer, error in
                            guard let self, let connection, !self.closed else { return }
                            guard error == nil, let answer,
                                  answer.prefix(2) == query.bytes.prefix(2),
                                  answer[answer.startIndex + 2] & 0x80 != 0 else {
                                self.finish(error ?? RouterProxyError.malformedReply); return
                            }
                            connection.cancel()
                            self.transport = nil
                            self.flow.writeDatagrams([answer], sentBy: [query.endpoint]) { [weak self] error in
                                guard let self else { return }
                                self.queue.async {
                                    guard !self.closed else { return }
                                    self.deadline?.cancel()
                                    if let error { self.finish(error) } else { self.processNextQuery() }
                                }
                            }
                        }
                    }
                }
            }
        } catch { finish(error) }
    }

    private func armDeadline(seconds: Int) {
        deadline?.cancel()
        let item = DispatchWorkItem { [weak self] in self?.finish(RouterProxyError.timedOut) }
        deadline = item
        queue.asyncAfter(deadline: .now() + .seconds(seconds), execute: item)
    }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true
        deadline?.cancel()
        deadline = nil
        transport?.cancel()
        transport = nil
        pending.removeAll()
        let reported = error == nil ? nil : RouterProxyError.closed.flowError
        flow.closeRead(reported)
        flow.closeWrite(reported)
        onFinish()
    }

    func cancel() { finish(RouterProxyError.closed) }
}
