import AppKit
import ArmorCore
import Darwin
import Foundation
import SwiftUI

@MainActor
enum ProtectionSelfTest {
    /// Exercises only our disposable child and the production pause controller.
    /// It does NOT enumerate or signal the user's Claude processes.
    static func run() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-selftest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                              attributes: [.posixPermissions: 0o700])
        let heartbeat = directory.appendingPathComponent("heartbeat")
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sh")
        child.arguments = ["-c", "while :; do printf '.' >> \"$1\"; /bin/sleep 0.05; done", "armor-selftest", heartbeat.path]
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        var controller: ProcessProtectionController?
        defer {
            if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) }
            controller?.shutdown()
            try? FileManager.default.removeItem(at: directory)
        }
        try child.run()
        try await Task.sleep(nanoseconds: 200_000_000)
        guard child.isRunning, let identity = ProtectedProcessCatalog.identity(for: child.processIdentifier),
              (try Data(contentsOf: heartbeat)).count > 0 else { throw SelfTestError.failed }
        let target = ProtectedProcessRecord(identity: identity, parentPID: getpid(), executablePath: "/bin/sh",
                                            processName: "armor-selftest", isClaudeDesktopRoot: false, isClaudeCodeInterpreter: false)
        let pauseController = ProcessProtectionController(automaticallyMonitor: false,
                                                         processReader: { child.isRunning ? [target] : [] })
        controller = pauseController
        try await Task.sleep(nanoseconds: 100_000_000)
        guard ProtectedProcessCatalog.isStopped(identity.pid) == true else { throw SelfTestError.failed }
        let pausedCount = try Data(contentsOf: heartbeat).count
        try await Task.sleep(nanoseconds: 200_000_000)
        guard try Data(contentsOf: heartbeat).count == pausedCount else { throw SelfTestError.failed }
        // A forbidden observation must not resume execution.
        let forbidden = try EgressObservation.decode(Data(#"{"ip":"203.0.113.1","country":"RU"}"#.utf8))
        pauseController.apply(forbidden, allowedCountryCode: "NL")
        guard ProtectedProcessCatalog.isStopped(identity.pid) == true else { throw SelfTestError.failed }
        let allowed = try EgressObservation.decode(Data(#"{"ip":"203.0.113.1","country":"NL"}"#.utf8))
        pauseController.apply(allowed, allowedCountryCode: "NL")
        try await Task.sleep(nanoseconds: 200_000_000)
        guard ProtectedProcessCatalog.isStopped(identity.pid) == false,
              try Data(contentsOf: heartbeat).count > pausedCount else { throw SelfTestError.failed }
    }
}

private enum SelfTestError: Error { case failed }

struct ProtectionSelfTestView: View {
    @State private var running = false
    @State private var result: String?
    var body: some View {
        GroupBox("Самотест паузы") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Проверяет остановку выполнения и продолжение собственного тестового процесса. Claude и VPN не затрагиваются. Это не тест отсутствия сетевых утечек.")
                    .font(AppTypography.description).foregroundStyle(.secondary)
                Button(running ? "Проверяем…" : "Проверить паузу и продолжение") {
                    running = true; result = nil
                    Task { @MainActor in
                        do {
                            try await ProtectionSelfTest.run()
                            result = "Готово: выполнение остановлено, запрещённое условие не сняло паузу, разрешённое — возобновило."
                        } catch {
                            result = "Самотест не пройден. Работа механизма паузы не подтверждена."
                        }
                        running = false
                    }
                }.disabled(running)
                if running { ProgressView().controlSize(.small) }
                if let result { Text(result).font(AppTypography.description).textSelection(.enabled) }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
}
