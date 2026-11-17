import ArmorCore
import Darwin
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class ProtectionSafetyTests: XCTestCase {
    private let target = ProtectedProcessRecord(
        identity: .init(pid: 900_001, startSeconds: 1, startMicroseconds: 2),
        parentPID: 1, executablePath: "/fixture/claude", processName: "claude",
        isClaudeDesktopRoot: false, isClaudeCodeInterpreter: false
    )

    private func observation(_ provider: EgressProvider = .ipWhoIS) throws -> EgressObservation {
        let json = provider == .ipWhoIS
            ? #"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#
            : #"{"ip":"203.0.113.7","country":"NL"}"#
        return try EgressObservation.decode(Data(json.utf8), provider: provider)
    }

    private func storage() throws -> UserDefaults {
        let name = "ProtectionSafetyTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        addTeardownBlock { defaults.removePersistentDomain(forName: name) }
        defaults.set(try JSONEncoder().encode(AppPreferences(allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
        return defaults
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<300 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("Request did not settle")
    }

    func testMissingCountrySetupCannotHideAFailedStopSignal() throws {
        let defaults = try storage()
        defaults.removeObject(forKey: "armor.preferences.v1")
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { _ in self.target.identity }, signaler: { _, _ in errno = EPERM; return -1 }
        )
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             processProtection: controller)
        XCTAssertEqual(model.protection.title, "Ошибка защиты")
        controller.apply(try observation(), allowedCountryCode: nil)
        guard case .failed = controller.status else { return XCTFail("Setup must not hide failed enforcement") }
    }

    func testFirstOfflineSnapshotAlwaysRevokesAnExistingPermission() async throws {
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try storage(), startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { try self.observation($0) }, processProtection: controller)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        model.receive(NetworkSnapshot(connectivity: .unavailable))
        XCTAssertFalse(model.protection.isOperational)
    }

    func testExternallyStoppedProcessIsNeverClaimedOrResumed() throws {
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { _ in self.target.identity }, signaler: { _, signal in signals.append(signal); return 0 },
            isStopped: { _ in true }
        )
        controller.apply(try observation(), allowedCountryCode: "NL")
        controller.shutdown()
        XCTAssertTrue(signals.isEmpty)
        XCTAssertTrue(controller.suspended.isEmpty)
    }

    func testExternalResumeCannotBypassUnsafePolicy() {
        var stopped = false
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { _ in self.target.identity }, signaler: { _, signal in
                signals.append(signal); stopped = signal == SIGSTOP; return 0
            }, isStopped: { _ in stopped }
        )
        XCTAssertTrue(stopped)
        stopped = false
        controller.enforce()
        XCTAssertTrue(stopped)
        XCTAssertEqual(signals, [SIGSTOP, SIGSTOP])
    }

    func testRecoveryResumesOnlyPreviouslyOwnedMatchingIdentity() throws {
        let reused = ProtectedProcessIdentity(pid: 900_002, startSeconds: 99, startMicroseconds: 0)
        var saved: Set<ProtectedProcessIdentity> = [target.identity, reused]
        var signals: [(pid_t, Int32)] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { pid in pid == self.target.identity.pid ? self.target.identity : nil },
            signaler: { signals.append(($0, $1)); return 0 }, isStopped: { _ in true },
            loadSuspended: { saved }, saveSuspended: { saved = $0 }
        )
        controller.apply(try observation(), allowedCountryCode: "NL")
        XCTAssertEqual(signals.map(\.0), [target.identity.pid])
        XCTAssertEqual(signals.map(\.1), [SIGCONT])
        XCTAssertTrue(saved.isEmpty)
    }

    func testUnreadableRecoveryLedgerCannotProduceActiveStatus() throws {
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { _ in self.target.identity }, signaler: { _, _ in 0 },
            loadSuspended: { throw CocoaError(.fileReadCorruptFile) }
        )
        controller.apply(try observation(), allowedCountryCode: "NL")
        guard case .failed = controller.status else { return XCTFail("Unreadable ownership must fail closed") }
    }

    func testFailedSignalDoesNotClaimSuccessfulPause() throws {
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { _ in self.target.identity }, signaler: { _, _ in errno = EPERM; return -1 }
        )
        guard case .failed = controller.status else { return XCTFail("Failed SIGSTOP must be visible") }
        let model = AppModel(defaults: try storage(), startsMonitoring: false, diagnosticsReader: { .notChecked },
                             processProtection: controller)
        XCTAssertEqual(model.protection.title, "Ошибка защиты")
        XCTAssertFalse(model.protection.isOperational)
    }

    func testWatchdogFailureRevokesPermissionAndFreshCheckCannotBypassIt() async throws {
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [self.target] },
            identityReader: { _ in self.target.identity }, signaler: { _, signal in signals.append(signal); return 0 }
        )
        let model = AppModel(defaults: try storage(), startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { try self.observation($0) }, processProtection: controller)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        model.updateWatchdogHealth(false)
        XCTAssertFalse(model.protection.isOperational)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertEqual(signals, [SIGSTOP, SIGCONT, SIGSTOP])
        model.updateWatchdogHealth(true)
        XCTAssertTrue(model.protection.isOperational)
        XCTAssertEqual(signals.last, SIGCONT)
    }

    func testExpiredCountryCannotBeTrustedFromAnOldVisibleResult() async throws {
        var date = Date(timeIntervalSince1970: 1_000)
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let defaults = try storage()
        defaults.removeObject(forKey: "armor.preferences.v1")
        let model = AppModel(defaults: defaults, startsMonitoring: false, now: { date },
                             diagnosticsReader: { .notChecked }, egressReader: { try self.observation($0) },
                             processProtection: controller)
        model.refreshExternalIP()
        await settle(model)
        date.addTimeInterval(61)
        model.trustCurrentCountry()
        XCTAssertNil(model.preferences.allowedCountryCode)
        XCTAssertFalse(model.protection.isOperational)
    }

    func testTimedOutRequestCannotReviveProtectionWithALateResponse() async throws {
        var date = Date(timeIntervalSince1970: 1_000)
        var pending: CheckedContinuation<EgressObservation, Error>?
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date },
                             diagnosticsReader: { .notChecked }, egressReader: { _ in
            try await withCheckedThrowingContinuation { pending = $0 }
        }, processProtection: controller)
        model.refreshExternalIP()
        for _ in 0..<300 {
            if pending != nil { break }
            await Task.yield()
        }
        let continuation = try XCTUnwrap(pending)
        date.addTimeInterval(26)
        model.expireExternalCheck()
        guard case .failed = model.externalCheck else { return XCTFail("Timeout must finish the visible request") }
        continuation.resume(returning: try observation())
        for _ in 0..<30 { await Task.yield() }
        XCTAssertFalse(model.protection.isOperational)
        guard case .failed = model.externalCheck else { return XCTFail("Cancelled response must stay discarded") }
    }

    func testSleepRevokesConsentAndLateConsensusCannotResume() async throws {
        var pending: CheckedContinuation<EgressObservation, Error>?
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        var requests = 0
        let model = AppModel(defaults: try storage(), startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { provider in
            requests += 1
            if requests <= 2 { return try self.observation(provider) }
            return try await withCheckedThrowingContinuation { pending = $0 }
        }, processProtection: controller)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        model.refreshExternalIP()
        for _ in 0..<300 {
            if pending != nil { break }
            await Task.yield()
        }
        let continuation = try XCTUnwrap(pending)
        model.prepareForSleep()
        continuation.resume(throwing: URLError(.cancelled))
        for _ in 0..<30 { await Task.yield() }
        XCTAssertFalse(model.protection.isOperational)
    }

    func testClockRollbackInvalidatesPreviouslyConfirmedCountry() async throws {
        var date = Date(timeIntervalSince1970: 1_000)
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date },
                             diagnosticsReader: { .notChecked }, egressReader: { try self.observation($0) },
                             processProtection: controller)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        date.addTimeInterval(-100)
        model.expireExternalCheck()
        XCTAssertFalse(model.protection.isOperational)
    }


    func testHungManualRefreshCannotKeepAnOldPermissionAlive() async throws {
        var date = Date(timeIntervalSince1970: 1_000)
        var pending: CheckedContinuation<EgressObservation, Error>?
        var requests = 0
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date },
                             diagnosticsReader: { .notChecked }, egressReader: { provider in
            requests += 1
            if requests <= 2 { return try self.observation(provider) }
            return try await withCheckedThrowingContinuation { pending = $0 }
        }, processProtection: controller)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        date.addTimeInterval(50)
        model.refreshExternalIP()
        for _ in 0..<300 {
            if pending != nil { break }
            await Task.yield()
        }
        let continuation = try XCTUnwrap(pending)
        date.addTimeInterval(11)
        model.expireExternalCheck()
        XCTAssertFalse(model.protection.isOperational)
        date.addTimeInterval(15)
        model.expireExternalCheck()
        guard case .failed = model.externalCheck else { return XCTFail("Hung request must eventually time out") }
        continuation.resume(returning: try observation())
        for _ in 0..<30 { await Task.yield() }
        XCTAssertEqual(requests, 3, "Cancelled first answer must not trigger the second provider")
        XCTAssertFalse(model.protection.isOperational)
    }

    func testActualPauseAndRecoveryAffectOnlyAnOwnedFixtureChild() async throws {
        // Never enumerate or signal user applications. Only this test's child is eligible.
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        defer {
            _ = Darwin.kill(child.processIdentifier, SIGCONT)
            if child.isRunning { child.terminate() }
            child.waitUntilExit()
        }
        let identity = try XCTUnwrap(ProtectedProcessCatalog.identity(for: child.processIdentifier))
        let record = ProtectedProcessRecord(identity: identity, parentPID: getpid(), executablePath: "/bin/sleep",
                                            processName: "fixture", isClaudeDesktopRoot: false,
                                            isClaudeCodeInterpreter: false)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let ledger = SuspensionLedger(directory: directory)
        let first = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [record] },
            loadSuspended: { try ledger.load() }, saveSuspended: { try ledger.save($0) }
        )
        for _ in 0..<100 {
            if ProtectedProcessCatalog.isStopped(identity.pid) == true { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(ProtectedProcessCatalog.isStopped(identity.pid), true)
        XCTAssertEqual(try ledger.load(), [identity])
        _ = first // Simulate replacement without calling the clean shutdown path.
        let recovered = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [record] },
            loadSuspended: { try ledger.load() }, saveSuspended: { try ledger.save($0) }
        )
        recovered.apply(try observation(), allowedCountryCode: "NL")
        for _ in 0..<100 {
            if ProtectedProcessCatalog.isStopped(identity.pid) == false { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(ProtectedProcessCatalog.isStopped(identity.pid), false)
        XCTAssertTrue(try ledger.load().isEmpty)
    }
}

final class SuspensionLedgerTests: XCTestCase {
    func testOnlyOneProtectionInstanceCanHoldTheLock() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        var first: ProtectionInstanceLock? = try ProtectionInstanceLock(directory: directory)
        XCTAssertNotNil(first)
        XCTAssertThrowsError(try ProtectionInstanceLock(directory: directory)) {
            guard case ProtectionInstanceLock.LockError.alreadyRunning = $0 else {
                return XCTFail("Expected existing instance, got \($0)")
            }
        }
        first = nil
        let replacement = try ProtectionInstanceLock(directory: directory)
        withExtendedLifetime(replacement) {}
    }

    func testLedgerRoundTripsOnlyIdentitiesWithPrivatePermissions() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let ledger = SuspensionLedger(directory: directory)
        XCTAssertTrue(try ledger.load().isEmpty)
        let value = ProtectedProcessIdentity(pid: 123, startSeconds: 456, startMicroseconds: 789)
        try ledger.save([value])
        XCTAssertEqual(try ledger.load(), [value])
        let permissions = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o700)
        let file = directory.appendingPathComponent("suspended-processes.json")
        let contents = try String(contentsOf: file, encoding: .utf8)
        XCTAssertFalse(contents.contains("/"))
        XCTAssertFalse(contents.contains("country"))
    }

    func testLedgerRejectsSymlinkAndMalformedOwnership() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let outside = root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let linked = root.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: outside)
        XCTAssertThrowsError(try SuspensionLedger(directory: linked).save([]))
        let ledger = SuspensionLedger(directory: outside)
        try ledger.save([])
        try Data("not json".utf8).write(to: outside.appendingPathComponent("suspended-processes.json"))
        XCTAssertThrowsError(try ledger.load())
    }
}
