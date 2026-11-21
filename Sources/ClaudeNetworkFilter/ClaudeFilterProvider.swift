import ArmorCore
import ArmorFilterIPC
import Darwin
import Foundation
import NetworkExtension
import Security

/// macOS supplies the socket owner's audit token. No TLS decryption, packet
/// logging, destination allowlist or changes to DNS, PF and routing tables.
final class ClaudeFilterProvider: NEFilterDataProvider, NSXPCListenerDelegate {
    private struct Lease {
        let policy: ClaudeNetworkPolicy
        let received: TimeInterval
    }
    private struct Owner: Hashable {
        let uid: uid_t
        let identity: ProtectedProcessIdentity
    }
    private let lock = NSLock()
    private var leases: [uid_t: Lease] = [:]
    private var known: [Owner: ProtectedApplication] = [:]
    private var flows: [UUID: (NEFilterSocketFlow, Owner, ProtectedApplication)] = [:]
    private var listener: NSXPCListener?
    private var timer: DispatchSourceTimer?
    private var ready = false

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        guard let service = (Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any])?["NEMachServiceName"] as? String else {
            completionHandler(NSError(domain: "ArmorClaudeFilter", code: 1)); return
        }
        let listener = NSXPCListener(machServiceName: service)
        listener.delegate = self; listener.resume(); self.listener = listener
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: .milliseconds(250))
        timer.setEventHandler { [weak self] in self?.revokeExpiredFlows() }
        timer.resume(); self.timer = timer
        apply(NEFilterSettings(rules: [], defaultAction: .filterData)) { [weak self] error in
            self?.lock.lock(); self?.ready = error == nil; self?.lock.unlock()
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock(); ready = false; leases = [:]; lock.unlock()
        revokeExpiredFlows()
        timer?.cancel(); timer = nil; listener?.invalidate(); listener = nil
        completionHandler()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier != 0,
              let team = Self.signingInfo(nil)?[kSecCodeInfoTeamIdentifier as String] as? String else { return false }
        // Foundation validates this against the peer's audit token on every call.
        connection.setCodeSigningRequirement("anchor apple generic and identifier \"app.russian-armor.desktop\" and certificate leaf[subject.OU] = \"\(team)\"")
        connection.exportedInterface = NSXPCInterface(with: ClaudeFilterProtocol.self)
        connection.exportedObject = Client(provider: self, uid: connection.effectiveUserIdentifier)
        connection.resume()
        return true
    }

    fileprivate func update(_ data: Data, uid: uid_t) -> Bool {
        guard data.count <= 1_048_576,
              let policy = try? JSONDecoder().decode(ClaudeNetworkPolicy.self, from: data),
              policy.processes.count <= 16_384 else { return false }
        lock.lock()
        leases[uid] = Lease(policy: policy, received: ProcessInfo.processInfo.systemUptime)
        for process in policy.processes {
            let owner = Owner(uid: uid, identity: process.identity)
            if Self.identity(pid: process.identity.pid, uid: uid) == process.identity { known[owner] = process.application }
        }
        let active = ready
        lock.unlock()
        revokeExpiredFlows()
        return active
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow,
              [AF_INET, AF_INET6].contains(socket.socketFamily),
              let token = flow.sourceAppAuditToken, token.count == MemoryLayout<audit_token_t>.size else { return .allow() }
        let words = token.withUnsafeBytes { Array($0.bindMemory(to: UInt32.self)) }
        let uid = uid_t(words[1]); let pid = pid_t(bitPattern: words[5])
        guard let identity = Self.identity(pid: pid, uid: uid) else { return .allow() }
        let owner = Owner(uid: uid, identity: identity)
        guard let application = application(for: owner, sourceToken: token) else { return .allow() }
        // Remember children immediately, including a child subsequently reparented
        // to launchd. It must not wait for the GUI's next one-second policy update.
        lock.lock(); known[owner] = application; lock.unlock()
        // All UDP, including arbitrary STUN/TURN ports and QUIC, is denied.
        // Unknown transport types are denied for Claude as well.
        guard socket.socketType == SOCK_STREAM, socket.socketProtocol == IPPROTO_TCP else { return .drop() }
        lock.lock()
        known[owner] = application
        let allowed = permits(owner, application)
        let hasCapacity = flows.count < 16_384
        if allowed && hasCapacity { flows[flow.identifier] = (socket, owner, application) }
        lock.unlock()
        guard allowed && hasCapacity else { return .drop() }
        let verdict = NEFilterNewFlowVerdict.filterDataVerdict(withFilterInbound: true, peekInboundBytes: 1, filterOutbound: true, peekOutboundBytes: 1)
        verdict.shouldReport = true
        return verdict
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        verdict(flow, count: readBytes.count)
    }
    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        verdict(flow, count: readBytes.count)
    }
    private func verdict(_ flow: NEFilterFlow, count: Int) -> NEFilterDataVerdict {
        lock.lock(); defer { lock.unlock() }
        guard let (_, owner, application) = flows[flow.identifier], permits(owner, application) else { return .drop() }
        // Never inspect or retain payload bytes. Recheck permission per chunk.
        return NEFilterDataVerdict(passBytes: count, peekBytes: 1)
    }
    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict { .allow() }
    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict { .allow() }
    override func handle(_ report: NEFilterReport) {
        if report.event == .flowClosed, let flow = report.flow {
            lock.lock(); flows.removeValue(forKey: flow.identifier); lock.unlock()
        }
    }
    private func permits(_ owner: Owner, _ application: ProtectedApplication) -> Bool {
        guard ready, let lease = leases[owner.uid] else { return false }
        return lease.policy.permits(application, udp: false, receivedAt: lease.received, now: ProcessInfo.processInfo.systemUptime)
    }
    private func revokeExpiredFlows() {
        lock.lock()
        let dropped = flows.filter { !permits($0.value.1, $0.value.2) }
        for id in dropped.keys { flows.removeValue(forKey: id) }
        known = known.filter { Self.identity(pid: $0.key.identity.pid, uid: $0.key.uid) == $0.key.identity }
        lock.unlock()
        for (_, (flow, _, _)) in dropped { update(flow, using: .drop(), for: .any) }
    }
    private func application(for source: Owner, sourceToken: Data) -> ProtectedApplication? {
        ProtectedProcessAncestry.application(for: source.identity) { pid in
            guard let info = Self.processInfo(pid: pid, uid: source.uid) else { return nil }
            let identity = ProtectedProcessIdentity(pid: pid, startSeconds: info.pbi_start_tvsec,
                                                   startMicroseconds: info.pbi_start_tvusec)
            let owner = Owner(uid: source.uid, identity: identity)
            lock.lock(); let cached = known[owner]; lock.unlock()
            let signing = cached == nil
                ? Self.signingInfo(pid == source.identity.pid ? sourceToken : nil, pid: pid) : nil
            // Revalidate around signing inspection: a reused PID is a new owner.
            guard Self.identity(pid: pid, uid: source.uid) == identity else { return nil }
            return .init(identity: identity, parentPID: pid_t(info.pbi_ppid),
                         application: cached ?? Self.signedApplication(signing))
        }
    }
    private static func signedApplication(_ info: [String: Any]?) -> ProtectedApplication? {
        guard let info, info[kSecCodeInfoTeamIdentifier as String] as? String == "Q6L2SF6YDW",
              let identifier = info[kSecCodeInfoIdentifier as String] as? String else { return nil }
        if identifier == "com.anthropic.claudefordesktop" || identifier.hasPrefix("com.anthropic.claudefordesktop.") {
            return .desktop
        }
        if identifier == "claude" || identifier == "com.anthropic.claude" { return .code }
        return nil
    }
    private static func identity(pid: pid_t, uid: uid_t) -> ProtectedProcessIdentity? {
        guard let info = processInfo(pid: pid, uid: uid) else { return nil }
        return .init(pid: pid, startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec)
    }
    private static func processInfo(pid: pid_t, uid: uid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
              info.pbi_uid == uid, info.pbi_ruid == uid, info.pbi_svuid == uid else { return nil }
        return info
    }
    private static func signingInfo(_ token: Data?, pid: pid_t? = nil) -> [String: Any]? {
        var code: SecCode?
        let status: OSStatus
        if let token {
            status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: token] as CFDictionary, [], &code)
        } else if let pid {
            status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code)
        } else {
            status = SecCodeCopySelf([], &code)
        }
        guard status == errSecSuccess, let code else { return nil }
        var info: CFDictionary?; var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess else { return nil }
        return info as? [String: Any]
    }
}

private final class Client: NSObject, ClaudeFilterProtocol {
    weak var provider: ClaudeFilterProvider?
    let uid: uid_t
    init(provider: ClaudeFilterProvider, uid: uid_t) { self.provider = provider; self.uid = uid }
    func updatePolicy(_ data: Data, withReply reply: @escaping (Bool) -> Void) { reply(provider?.update(data, uid: uid) == true) }
}
