import AppKit
import ArmourCore
import Combine
import Darwin
import Foundation

struct ProtectedProcessIdentity: Hashable, Sendable {
    let pid: pid_t
    let startSeconds: UInt64
    let startMicroseconds: UInt64
}

struct ProtectedProcessRecord: Equatable, Sendable {
    let identity: ProtectedProcessIdentity
    let parentPID: pid_t
    let executablePath: String
    let processName: String
    let isClaudeDesktopRoot: Bool
    let isClaudeCodeInterpreter: Bool
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
        var queue = records.filter { record in
            if record.isClaudeDesktopRoot || record.isClaudeCodeInterpreter { return true }
            let executable = URL(fileURLWithPath: record.executablePath).lastPathComponent.lowercased()
            return codeExecutableNames.contains(executable)
                || codeExecutableNames.contains(record.processName.lowercased())
                || record.executablePath.contains("/.local/share/claude/versions/")
        }
        var index = 0
        while index < queue.count {
            let record = queue[index]
            index += 1
            guard selected.insert(record.identity).inserted else { continue }
            queue.append(contentsOf: byParent[record.identity.pid] ?? [])
        }
        return records.filter { selected.contains($0.identity) }
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
    private var reason = "Проверяем внешний адрес."
    private let processReader: ProcessReader
    private let identityReader: IdentityReader
    private let signaler: Signaler
    private var timer: AnyCancellable?

    init(
        automaticallyMonitor: Bool = true,
        processReader: @escaping ProcessReader = ProtectedProcessCatalog.current,
        identityReader: @escaping IdentityReader = ProtectedProcessCatalog.identity,
        signaler: @escaping Signaler = { Darwin.kill($0, $1) }
    ) {
        self.processReader = processReader
        self.identityReader = identityReader
        self.signaler = signaler
        enforce()
        if automaticallyMonitor {
            timer = Timer.publish(every: 0.25, on: .main, in: .common)
                .autoconnect()
                .sink { [weak self] _ in self?.enforce() }
        }
    }

    func apply(_ observation: EgressObservation, allowedCountryCode: String?) {
        guard let allowedCountryCode else {
            isSafe = false
            reason = "Выберите страну VPN. До этого Claude остаётся на паузе."
            enforce()
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

    func pause(_ reason: String) {
        isSafe = false
        self.reason = reason
        enforce()
    }

    func requireCountry(currentCountryCode: String? = nil) {
        isSafe = false
        reason = "Выберите страну VPN. До этого Claude остаётся на паузе."
        enforce()
        status = .needsAllowedCountry(currentCountryCode, suspended.count)
    }

    func shutdown() {
        timer?.cancel()
        timer = nil
        isSafe = true
        resumeSuspended()
    }

    private func enforce() {
        if isSafe {
            if !suspended.isEmpty { updateResumedStatus() }
            return
        }
        let records = processReader()
        var failures = 0
        for record in records where !suspended.contains(record.identity) {
            guard identityReader(record.identity.pid) == record.identity else { continue }
            if signaler(record.identity.pid, SIGSTOP) == 0 {
                suspended.insert(record.identity)
            } else if errno != ESRCH {
                failures += 1
            }
        }
        suspended = suspended.filter { identityReader($0.pid) == $0 }
        status = failures == 0
            ? .paused(reason, suspended.count)
            : .failed("Не удалось поставить на паузу \(failures) процессов Claude.")
    }

    private func updateResumedStatus() {
        resumeSuspended()
        if !suspended.isEmpty {
            status = .failed("Не удалось возобновить \(suspended.count) процессов Claude. Повторяем попытку.")
        } else if let safeCountry {
            status = .active(safeCountry, processReader().count)
        }
    }

    private func resumeSuspended() {
        for identity in suspended {
            guard identityReader(identity.pid) == identity else {
                suspended.remove(identity)
                continue
            }
            if signaler(identity.pid, SIGCONT) == 0 || errno == ESRCH {
                suspended.remove(identity)
            }
        }
    }
}
