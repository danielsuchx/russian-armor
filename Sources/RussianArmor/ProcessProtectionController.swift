import AppKit
import ArmorCore
import Combine
import Darwin
import Foundation

enum ProtectedProcessTerminationError: Error, LocalizedError {
    case processesRemain(Int)

    var errorDescription: String? {
        switch self {
        case .processesRemain(let count):
            return "Не удалось закрыть \(count) процессов Claude. Russian Armor продолжает работать."
        }
    }
}

struct ProtectedProcessRecord: Equatable, Sendable {
    let identity: ProtectedProcessIdentity
    let parentPID: pid_t
    let executablePath: String
    let processName: String
    let isClaudeDesktopRoot: Bool
    let isClaudeCodeInterpreter: Bool
    var application: ProtectedApplication = .code
}

enum ProtectedProcessCatalog {
    private static let desktopBundleIdentifier = "com.anthropic.claudefordesktop"
    private static let codeExecutableNames: Set<String> = ["claude", "claude-code"]
    private static let interpreterNames: Set<String> = ["node", "bun", "deno"]
    private static let claudeCodeArgumentMarker = "@anthropic-ai/claude-code"
    private static let initialProcessCapacity = 2_048

    static func current() -> [ProtectedProcessRecord] {
        let uid = getuid()
        guard uid != 0, geteuid() == uid else { return [] }
        let desktopPIDs = Set(NSWorkspace.shared.runningApplications.compactMap { application -> pid_t? in
            application.bundleIdentifier == desktopBundleIdentifier ? application.processIdentifier : nil
        })
        var capacity = initialProcessCapacity
        var pids: [pid_t]
        var bytes: Int32
        repeat {
            pids = [pid_t](repeating: 0, count: capacity)
            bytes = pids.withUnsafeMutableBytes {
                proc_listpids(UInt32(PROC_UID_ONLY), uid, $0.baseAddress, Int32($0.count))
            }
            guard bytes > 0 else { return [] }
            if Int(bytes) < pids.count * MemoryLayout<pid_t>.stride { break }
            guard capacity <= Int(Int32.max) / MemoryLayout<pid_t>.stride / 2 else { return [] }
            capacity *= 2
        } while true
        let count = Int(bytes) / MemoryLayout<pid_t>.stride
        let records = pids.prefix(count).compactMap { record(pid: $0, uid: uid, desktopPIDs: desktopPIDs) }
        return protectedRecords(from: records)
    }

    static func identity(for pid: pid_t) -> ProtectedProcessIdentity? {
        guard let info = processInfo(pid), belongsToUser(info, getuid()) else { return nil }
        return .init(pid: pid, startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec)
    }

    static func protectedRecords(from records: [ProtectedProcessRecord]) -> [ProtectedProcessRecord] {
        let byParent = Dictionary(grouping: records, by: \.parentPID)
        var selected = Set<ProtectedProcessIdentity>()
        var applications: [ProtectedProcessIdentity: ProtectedApplication] = [:]
        var queue = records.filter { record in
            if record.isClaudeDesktopRoot || record.isClaudeCodeInterpreter { return true }
            let executable = URL(fileURLWithPath: record.executablePath).lastPathComponent.lowercased()
            return codeExecutableNames.contains(executable)
                || codeExecutableNames.contains(record.processName.lowercased())
                || record.executablePath.contains("/.local/share/claude/versions/")
        }.map { record -> ProtectedProcessRecord in
            var root = record
            root.application = record.isClaudeDesktopRoot ? .desktop : .code
            return root
        }
        let roots = Set(queue.map(\.identity))
        var index = 0
        while index < queue.count {
            let record = queue[index]
            index += 1
            guard selected.insert(record.identity).inserted else { continue }
            applications[record.identity] = record.application
            queue.append(contentsOf: (byParent[record.identity.pid] ?? []).filter { !roots.contains($0.identity) }.map {
                var child = $0
                child.application = record.application
                return child
            })
        }
        return records.compactMap { record in
            guard let application = applications[record.identity] else { return nil }
            var selected = record
            selected.application = application
            return selected
        }
    }

    private static func record(pid: pid_t, uid: uid_t, desktopPIDs: Set<pid_t>) -> ProtectedProcessRecord? {
        guard pid > 1, pid != getpid(), let info = processInfo(pid), belongsToUser(info, uid) else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        let path = length > 0 ? String(cString: buffer) : ""
        var mutableInfo = info
        let processName = withUnsafeBytes(of: &mutableInfo.pbi_name) {
            String(bytes: $0.prefix(while: { $0 != 0 }), encoding: .utf8)
        } ?? ""
        let executableName = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        let isInterpreter = interpreterNames.contains(executableName)
            || interpreterNames.contains(processName.lowercased())
        return .init(
            identity: .init(pid: pid, startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec),
            parentPID: pid_t(info.pbi_ppid), executablePath: path, processName: processName,
            isClaudeDesktopRoot: desktopPIDs.contains(pid),
            isClaudeCodeInterpreter: isInterpreter && commandLineContainsClaudeCode(pid: pid)
        )
    }

    private static func commandLineContainsClaudeCode(pid: pid_t) -> Bool {
        var mib = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size,
              size <= 1_048_576 else { return false }
        var bytes = [UInt8](repeating: 0, count: size)
        let result = bytes.withUnsafeMutableBytes { storage in
            sysctl(&mib, u_int(mib.count), storage.baseAddress, &size, nil, 0)
        }
        guard result == 0, size <= bytes.count else { return false }
        bytes.removeSubrange(size..<bytes.count)

        var argumentCount: Int32 = 0
        withUnsafeMutableBytes(of: &argumentCount) { destination in
            bytes.withUnsafeBytes { source in
                destination.copyBytes(from: source.prefix(MemoryLayout<Int32>.size))
            }
        }
        guard argumentCount > 0, argumentCount < 4_096 else { return false }

        var cursor = MemoryLayout<Int32>.size
        while cursor < bytes.count, bytes[cursor] != 0 { cursor += 1 } // executable path
        while cursor < bytes.count, bytes[cursor] == 0 { cursor += 1 }
        for _ in 0..<Int(argumentCount) {
            let start = cursor
            while cursor < bytes.count, bytes[cursor] != 0 { cursor += 1 }
            if start < cursor {
                let argument = String(decoding: bytes[start..<cursor], as: UTF8.self).lowercased()
                if argument.contains(claudeCodeArgumentMarker) { return true }
            }
            while cursor < bytes.count, bytes[cursor] == 0 { cursor += 1 }
            if cursor >= bytes.count { break }
        }
        return false
    }

    static func isStopped(_ pid: pid_t) -> Bool? {
        processInfo(pid).map { Int32($0.pbi_status) == SSTOP }
    }

    private static func processInfo(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let received = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        return received == MemoryLayout<proc_bsdinfo>.size ? info : nil
    }

    private static func belongsToUser(_ info: proc_bsdinfo, _ uid: uid_t) -> Bool {
        info.pbi_uid == uid && info.pbi_ruid == uid && info.pbi_svuid == uid
    }
}

@MainActor
final class ProcessProtectionController: ObservableObject {
    enum Status: Equatable {
        case checking(Int)
        case needsAllowedCountry(String?, Int)
        case active(String, Int)
        case paused(String, Int)
        case failed(String)
    }

    typealias ProcessReader = () -> [ProtectedProcessRecord]
    typealias IdentityReader = (pid_t) -> ProtectedProcessIdentity?
    typealias Signaler = (pid_t, Int32) -> Int32

    @Published private(set) var status: Status = .checking(0)
    private(set) var suspended = Set<ProtectedProcessIdentity>()
    private var isSafe = false
    private var safeCountry: String?
    private var applicationDecisions: [ProtectedApplication: AccessDecision]?
    private var reason = "Проверяем внешний адрес."
    private let processReader: ProcessReader
    private let identityReader: IdentityReader
    private let signaler: Signaler
    private let isStopped: (pid_t) -> Bool?
    private let saveSuspended: (Set<ProtectedProcessIdentity>) throws -> Void
    private let automaticallyMonitor: Bool
    private var persistenceFailed = false
    private var recoveryFailed = false
    private var isTerminatingProcesses = false
    private var lastPersisted: Set<ProtectedProcessIdentity>?
    private var timer: AnyCancellable?

    init(
        automaticallyMonitor: Bool = true,
        processReader: @escaping ProcessReader = ProtectedProcessCatalog.current,
        identityReader: @escaping IdentityReader = ProtectedProcessCatalog.identity,
        signaler: @escaping Signaler = { Darwin.kill($0, $1) },
        isStopped: @escaping (pid_t) -> Bool? = ProtectedProcessCatalog.isStopped,
        loadSuspended: () throws -> Set<ProtectedProcessIdentity> = { [] },
        saveSuspended: @escaping (Set<ProtectedProcessIdentity>) throws -> Void = { _ in }
    ) {
        self.automaticallyMonitor = automaticallyMonitor
        self.processReader = processReader
        self.identityReader = identityReader
        self.signaler = signaler
        self.isStopped = isStopped
        self.saveSuspended = saveSuspended
        do {
            suspended = try loadSuspended().filter { identityReader($0.pid) == $0 }
        } catch {
            persistenceFailed = true
            recoveryFailed = true
        }
        enforce()
        if automaticallyMonitor { startMonitoring() }
    }

    func monitoredProcessIdentities() -> Set<TrafficProcess.ID> {
        Set(processReader().map {
            TrafficProcess.ID(pid: $0.identity.pid, startSeconds: $0.identity.startSeconds,
                              startMicroseconds: $0.identity.startMicroseconds)
        })
    }

    func apply(_ observation: EgressObservation, allowedCountryCode: String?) {
        applicationDecisions = nil
        guard let allowedCountryCode else {
            isSafe = false
            reason = "Выберите страну VPN. До этого Claude остаётся на паузе."
            enforce()
            if case .failed = status { return }
            status = .needsAllowedCountry(observation.countryCode, suspended.count)
            return
        }
        guard observation.countryCode == allowedCountryCode else {
            pause("Выход через \(observation.countryCode), разрешена страна \(allowedCountryCode).")
            return
        }
        isSafe = true
        safeCountry = allowedCountryCode
        updateResumedStatus()
    }

    func apply(_ decisions: [ProtectedApplication: AccessDecision], country: String) {
        applicationDecisions = decisions
        isSafe = false
        safeCountry = country
        enforce()
    }

    func pause(_ reason: String) {
        applicationDecisions = nil
        isSafe = false
        self.reason = reason
        enforce()
    }

    func requireCountry(currentCountryCode: String? = nil) {
        applicationDecisions = nil
        isSafe = false
        reason = "Выберите страну VPN. До этого Claude остаётся на паузе."
        enforce()
        if case .failed = status { return }
        status = .needsAllowedCountry(currentCountryCode, suspended.count)
    }

    func shutdown() {
        timer?.cancel()
        timer = nil
        if isTerminatingProcesses {
            suspended.removeAll()
            persist()
            return
        }
        isSafe = true
        resumeSuspended()
    }

    /// Close every Claude process identified at shutdown before Russian Armor
    /// itself exits. A graceful SIGTERM is attempted first. Processes owned by
    /// our pause ledger receive SIGCONT only after SIGTERM is pending, so they
    /// can terminate without being resumed for ordinary work. SIGKILL is the
    /// bounded fallback; failure keeps Russian Armor alive.
    func terminateProtectedProcesses() async throws {
        guard !isTerminatingProcesses else { return }
        isTerminatingProcesses = true
        applicationDecisions = nil
        timer?.cancel()
        timer = nil
        isSafe = false

        var targets = Set(currentProtectedIdentities())
        var terminated = Set<ProtectedProcessIdentity>()

        func absorbAndTerminateNewTargets() {
            targets.formUnion(currentProtectedIdentities())
            for identity in targets.subtracting(terminated) {
                guard identityReader(identity.pid) == identity else {
                    terminated.insert(identity)
                    continue
                }
                _ = signaler(identity.pid, SIGTERM)
                if suspended.remove(identity) != nil {
                    persist()
                    _ = signaler(identity.pid, SIGCONT)
                }
                terminated.insert(identity)
            }
        }

        absorbAndTerminateNewTargets()
        for _ in 0..<30 {
            absorbAndTerminateNewTargets()
            if liveIdentities(in: targets).isEmpty && currentProtectedIdentities().isEmpty {
                suspended.removeAll()
                persist()
                return
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }

        targets.formUnion(currentProtectedIdentities())
        for identity in liveIdentities(in: targets) {
            guard identityReader(identity.pid) == identity else { continue }
            _ = signaler(identity.pid, SIGKILL)
        }
        for _ in 0..<10 {
            targets.formUnion(currentProtectedIdentities())
            let remaining = liveIdentities(in: targets)
            if remaining.isEmpty && currentProtectedIdentities().isEmpty {
                suspended.removeAll()
                persist()
                return
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }

        let remaining = liveIdentities(in: targets).count
        isTerminatingProcesses = false
        reason = "Не удалось закрыть все процессы Claude. Защита остаётся включённой."
        if automaticallyMonitor { startMonitoring() }
        enforce()
        throw ProtectedProcessTerminationError.processesRemain(max(remaining, 1))
    }

    func enforce() {
        if let applicationDecisions {
            enforceApplications(applicationDecisions)
            return
        }
        if isSafe {
            if !suspended.isEmpty { updateResumedStatus() }
            return
        }
        let records = processReader()
        var failures = 0
        for record in records {
            guard identityReader(record.identity.pid) == record.identity else { continue }
            if suspended.contains(record.identity) {
                // An external SIGCONT must not bypass an unsafe policy.
                if isStopped(record.identity.pid) == false,
                   signaler(record.identity.pid, SIGSTOP) != 0, errno != ESRCH { failures += 1 }
                continue
            }
            // A process stopped by someone else is not ours to resume later.
            guard isStopped(record.identity.pid) != true else { continue }
            // Record ownership before sending the signal so a crash immediately
            // after SIGSTOP cannot strand a process forever on the next launch.
            suspended.insert(record.identity)
            persist()
            if signaler(record.identity.pid, SIGSTOP) != 0 {
                suspended.remove(record.identity)
                if errno != ESRCH { failures += 1 }
            }
        }
        suspended = suspended.filter { identityReader($0.pid) == $0 }
        persist()
        if persistenceFailed {
            status = .failed("Не удалось сохранить состояние паузы. Claude остаётся приостановлен; проверьте доступ к локальному хранилищу.")
            return
        }
        status = failures == 0
            ? .paused(reason, suspended.count)
            : .failed("Не удалось поставить на паузу \(failures) процессов Claude.")
    }

    private func enforceApplications(_ decisions: [ProtectedApplication: AccessDecision]) {
        let records = processReader()
        let denied = records.filter { decisions[$0.application]?.allowed != true }
        // Pause newly forbidden processes before resuming newly allowed ones.
        let savedDecisions = applicationDecisions
        applicationDecisions = nil
        let allAllowed = ProtectedApplication.allCases.allSatisfy { decisions[$0]?.allowed == true }
        reason = ProtectedApplication.allCases.compactMap { application -> String? in
            guard let decision = decisions[application], !decision.allowed else { return nil }
            return "\(application.title): \(decision.explanation)"
        }.joined(separator: " ")
        // Reuse the same PID/ownership/ledger checks as global fail-closed pauses.
        var failures = 0
        for record in denied {
            let identity = record.identity
            guard identityReader(identity.pid) == identity else { continue }
            if suspended.contains(identity) {
                if isStopped(identity.pid) == false,
                   signaler(identity.pid, SIGSTOP) != 0, errno != ESRCH { failures += 1 }
                continue
            }
            guard isStopped(identity.pid) != true else { continue }
            suspended.insert(identity)
            persist()
            if signaler(identity.pid, SIGSTOP) != 0 {
                suspended.remove(identity)
                if errno != ESRCH { failures += 1 }
            }
        }
        suspended = suspended.filter { identityReader($0.pid) == $0 }
        persist()
        // Never resume any process if stop or ledger integrity failed.
        if failures == 0, !persistenceFailed {
            let allowed = Set(records.filter { decisions[$0.application]?.allowed == true }.map(\.identity))
            resumeSuspended(eligible: allowed)
        }
        applicationDecisions = savedDecisions
        if persistenceFailed || failures > 0 {
            // A partial enforcement failure must not leave the other application
            // running under a global "protection failed" state.
            applicationDecisions = nil
            reason = "Не удалось применить правила приложений. Допуск закрыт."
            enforce()
            status = .failed("Не удалось применить правила или сохранить состояние паузы. Допуск закрыт.")
            return
        } else if suspended.contains(where: { identity in
            records.contains { $0.identity == identity && decisions[$0.application]?.allowed == true }
        }) {
            status = .failed("Не удалось возобновить разрешённые процессы. Повторяем попытку.")
        } else if allAllowed, suspended.isEmpty, let safeCountry {
            status = .active(safeCountry, records.count)
        } else {
            status = .paused(reason.isEmpty ? "Не все процессы удалось сопоставить с правилами." : reason, suspended.count)
        }
    }

    private func updateResumedStatus() {
        persist()
        guard !persistenceFailed else {
            isSafe = false
            enforce()
            return
        }
        resumeSuspended()
        if !suspended.isEmpty {
            status = .failed("Не удалось возобновить \(suspended.count) процессов Claude. Повторяем попытку.")
        } else if persistenceFailed {
            isSafe = false
            enforce()
        } else if let safeCountry {
            status = .active(safeCountry, processReader().count)
        }
    }

    private func resumeSuspended(eligible: Set<ProtectedProcessIdentity>? = nil) {
        for identity in Array(suspended) {
            if let eligible, !eligible.contains(identity) { continue }
            guard identityReader(identity.pid) == identity else {
                suspended.remove(identity)
                continue
            }
            if signaler(identity.pid, SIGCONT) == 0 || errno == ESRCH {
                suspended.remove(identity)
            }
        }
        persist()
    }

    private func currentProtectedIdentities() -> [ProtectedProcessIdentity] {
        processReader().compactMap { record in
            identityReader(record.identity.pid) == record.identity ? record.identity : nil
        }
    }

    private func liveIdentities(in identities: Set<ProtectedProcessIdentity>) -> Set<ProtectedProcessIdentity> {
        Set(identities.filter { identityReader($0.pid) == $0 })
    }

    private func startMonitoring() {
        guard timer == nil else { return }
        timer = Timer.publish(every: 0.25, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in self?.enforce() }
    }


    private func persist() {
        guard !recoveryFailed else { return }
        guard persistenceFailed || lastPersisted != suspended else { return }
        do {
            try saveSuspended(suspended)
            lastPersisted = suspended
            persistenceFailed = false
        } catch {
            persistenceFailed = true
        }
    }
}
