import Darwin
import Foundation

struct WatchdogRequest: Equatable {
    static let flag = "--russian-armour-watchdog"

    let parent: ProtectedProcessIdentity
    let cleanExitURL: URL
    let bundleURL: URL

    init?(arguments: [String]) {
        guard arguments.count == 7,
              arguments[1] == Self.flag,
              let pid = pid_t(arguments[2]),
              let seconds = UInt64(arguments[3]),
              let microseconds = UInt64(arguments[4]),
              pid > 1 else { return nil }
        parent = .init(pid: pid, startSeconds: seconds, startMicroseconds: microseconds)
        cleanExitURL = URL(fileURLWithPath: arguments[5])
        bundleURL = URL(fileURLWithPath: arguments[6])
    }

    var arguments: [String] {
        [Self.flag, String(parent.pid), String(parent.startSeconds), String(parent.startMicroseconds),
         cleanExitURL.path, bundleURL.path]
    }
}

final class ApplicationWatchdog: @unchecked Sendable {
    private let request: WatchdogRequest
    private let executableURL: URL
    private var helper: Process?
    private var cleanExitMarked = false
    private var lastStartError: (error: WatchdogError, timestamp: Date)?

    private init(request: WatchdogRequest, executableURL: URL) {
        self.request = request
        self.executableURL = executableURL
        _ = try? ensureRunning()
    }

    static func start(bundle: Bundle = .main) -> ApplicationWatchdog? {
        guard bundle.bundleURL.pathExtension == "app",
              let executableURL = bundle.executableURL,
              let parent = ProtectedProcessCatalog.identity(for: getpid()) else { return nil }
        let cleanExitURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("app.russian-armour.watchdog.\(UUID().uuidString).clean")
        let request = WatchdogRequest(
            parent: parent,
            cleanExitURL: cleanExitURL,
            bundleURL: bundle.bundleURL
        )
        return ApplicationWatchdog(request: request, executableURL: executableURL)
    }

    enum WatchdogError: LocalizedError {
        case failedToStart(String)
        case markerFileCleanupFailed(String)

        var errorDescription: String? {
            switch self {
            case .failedToStart(let reason):
                return "Watchdog: не удалось запустить: \(reason)"
            case .markerFileCleanupFailed(let reason):
                return "Watchdog: не удалось очистить файл маркера: \(reason)"
            }
        }
    }

    func ensureRunning() throws {
        guard !cleanExitMarked, helper?.isRunning != true else { return }
        let process = Process()
        process.executableURL = executableURL
        process.arguments = request.arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            helper = process
            lastStartError = nil
        } catch {
            let error = WatchdogError.failedToStart(error.localizedDescription)
            lastStartError = (error, Date())
            throw error
        }
    }

    func markCleanExit() throws {
        cleanExitMarked = true
        do {
            try Data().write(to: request.cleanExitURL, options: .atomic)
        } catch {
            throw WatchdogError.markerFileCleanupFailed(error.localizedDescription)
        }
    }

    var isHealthy: Bool {
        guard !cleanExitMarked else { return true }
        return helper?.isRunning == true && lastStartError == nil
    }

    var statusMessage: String? {
        if let (error, _) = lastStartError {
            return error.errorDescription
        }
        if cleanExitMarked { return nil }
        if helper?.isRunning == true { return nil }
        return "Watchdog не запущен"
    }

    static func runHelperIfRequested(arguments: [String] = CommandLine.arguments) -> Bool {
        guard let request = WatchdogRequest(arguments: arguments) else { return false }
        while ProtectedProcessCatalog.identity(for: request.parent.pid) == request.parent {
            usleep(100_000)
        }
        if FileManager.default.fileExists(atPath: request.cleanExitURL.path) {
            try? FileManager.default.removeItem(at: request.cleanExitURL)
            return true
        }

        pauseProtectedProcesses()
        let opener = Process()
        opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        opener.arguments = ["-n", request.bundleURL.path]
        opener.standardInput = FileHandle.nullDevice
        opener.standardOutput = FileHandle.nullDevice
        opener.standardError = FileHandle.nullDevice
        try? opener.run()
        opener.waitUntilExit()
        return true
    }

    private static func pauseProtectedProcesses() {
        for record in ProtectedProcessCatalog.current()
        where ProtectedProcessCatalog.identity(for: record.identity.pid) == record.identity {
            _ = Darwin.kill(record.identity.pid, SIGSTOP)
        }
    }
}

private extension WatchdogRequest {
    init(parent: ProtectedProcessIdentity, cleanExitURL: URL, bundleURL: URL) {
        self.parent = parent
        self.cleanExitURL = cleanExitURL
        self.bundleURL = bundleURL
    }
}
