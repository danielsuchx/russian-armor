import Darwin
import Foundation
import Combine
import XCTest
import ArmorCore
@testable import RussianArmor

@MainActor
final class ProcessProtectionControllerTests: XCTestCase {
    private func identity(_ pid: pid_t, start: UInt64 = 1) -> ProtectedProcessIdentity {
        .init(pid: pid, startSeconds: start, startMicroseconds: 0)
    }

    private func record(_ pid: pid_t, parent: pid_t = 1, path: String,
                        name: String? = nil, desktop: Bool = false, npmClaude: Bool = false,
                        start: UInt64 = 1) -> ProtectedProcessRecord {
        .init(identity: identity(pid, start: start), parentPID: parent,
              executablePath: path, processName: name ?? URL(fileURLWithPath: path).lastPathComponent,
              isClaudeDesktopRoot: desktop, isClaudeCodeInterpreter: npmClaude)
    }

    private func observation(_ country: String) throws -> EgressObservation {
        try EgressObservation.decode(
            Data(#"{"ip":"203.0.113.7","country":"\#(country)"}"#.utf8),
            checkedAt: Date(timeIntervalSince1970: 1)
        )
    }

    func testCatalogSelectsDesktopCodeAndAllDescendants() {
        let records = [
            record(10, path: "/Applications/Claude.app/Contents/MacOS/Claude", desktop: true),
            record(11, parent: 10, path: "/Applications/Claude.app/Contents/Frameworks/helper"),
            record(12, parent: 11, path: "/usr/bin/git"),
            record(20, path: "/fixture/home/.local/bin/claude"),
            record(21, parent: 20, path: "/bin/zsh"),
            record(22, path: "/fixture/home/.local/share/claude/versions/2.1.325", name: "2.1.325"),
            record(30, path: "/usr/bin/node"),
            record(31, path: "/opt/homebrew/bin/node", npmClaude: true),
            record(32, parent: 31, path: "/usr/bin/git")
        ]
        let selected = Set(ProtectedProcessCatalog.protectedRecords(from: records).map(\.identity.pid))
        XCTAssertEqual(selected, [10, 11, 12, 20, 21, 22, 31, 32])
    }

    func testStartsFailClosedAndResumesOnlyAfterAllowedCountry() throws {
        let target = record(42, path: "/usr/local/bin/claude")
        var liveIdentity: ProtectedProcessIdentity? = target.identity
        var signals: [(pid_t, Int32)] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { [target] },
            identityReader: { _ in liveIdentity },
            signaler: { signals.append(($0, $1)); return 0 }
        )
        XCTAssertEqual(signals.map(\.1), [SIGSTOP])

        controller.apply(try observation("DE"), allowedCountryCode: "NL")
        XCTAssertEqual(signals.map(\.1), [SIGSTOP])
        guard case .paused = controller.status else { return XCTFail("Mismatched country must stay paused") }

        controller.apply(try observation("NL"), allowedCountryCode: "NL")
        XCTAssertEqual(signals.map(\.1), [SIGSTOP, SIGCONT])
        XCTAssertTrue(controller.suspended.isEmpty)
        guard case .active("NL", _) = controller.status else { return XCTFail("Allowed country must resume") }

        controller.pause("Сеть изменилась")
        XCTAssertEqual(signals.map(\.1), [SIGSTOP, SIGCONT, SIGSTOP])
        liveIdentity = nil
        controller.shutdown()
        XCTAssertEqual(signals.map(\.1), [SIGSTOP, SIGCONT, SIGSTOP], "Exited or reused PID must not receive SIGCONT")
    }

    func testAllowedIdleSkipsScansButRevokingAccessDiscoversAndStopsNewChildren() {
        var records: [ProtectedProcessRecord] = []
        var reads = 0
        var stopped = Set<pid_t>()
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { reads += 1; return records },
            identityReader: { pid in records.first { $0.identity.pid == pid }?.identity },
            signaler: { pid, signal in
                if signal == SIGSTOP { stopped.insert(pid) }
                if signal == SIGCONT { stopped.remove(pid) }
                return 0
            },
            isStopped: { stopped.contains($0) }
        )
        let allow = AccessRules(allowedCountries: ["DE"]).evaluate(ip: "203.0.113.7", countries: ["DE"])
        let deny = AccessRules(allowedCountries: ["NL"]).evaluate(ip: "203.0.113.7", countries: ["DE"])
        controller.apply([.desktop: allow, .code: allow], country: "DE")
        let idleReads = reads
        var notifications = 0
        let subscription = controller.objectWillChange.sink { notifications += 1 }
        defer { subscription.cancel() }
        for _ in 0..<20 { controller.enforce() }
        XCTAssertEqual(reads, idleReads, "Allowed idle ticks must not enumerate all user processes")
        XCTAssertEqual(notifications, 0, "An unchanged status must not redraw the interface")

        records = [record(90001, path: "/fixture/claude")]
        controller.apply([.desktop: allow, .code: deny], country: "DE")
        XCTAssertTrue(stopped.contains(90001), "Revoking access must immediately scan even after idle ticks")
        records.append(record(90002, parent: 90001, path: "/bin/sh"))
        controller.enforce()
        XCTAssertTrue(stopped.contains(90002), "Denied apps must still discover new descendants on every tick")
        stopped.remove(90002)
        controller.enforce()
        XCTAssertTrue(stopped.contains(90002), "An external resume must not bypass the denied policy")

        controller.apply([.desktop: allow, .code: allow], country: "DE")
        XCTAssertTrue(stopped.isEmpty)
        records.append(record(90003, parent: 90001, path: "/usr/bin/git"))
        XCTAssertEqual(controller.monitoredProcessIdentities().count, 3)
        XCTAssertEqual(controller.status, .active("DE", 3), "The route monitor must still refresh process discovery and counts")
    }

    func testShutdownTerminatesPausedClaudeBeforeReleasingApplication() async throws {
        let target = record(43, path: "/usr/local/bin/claude")
        var liveIdentity: ProtectedProcessIdentity? = target.identity
        var stopped = false
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { liveIdentity == nil ? [] : [target] },
            identityReader: { _ in liveIdentity },
            signaler: { _, signal in
                signals.append(signal)
                if signal == SIGSTOP { stopped = true }
                if signal == SIGCONT {
                    stopped = false
                    liveIdentity = nil // SIGTERM was already pending, so the process exits.
                }
                return 0
            },
            isStopped: { _ in stopped }
        )
        XCTAssertEqual(signals, [SIGSTOP])

        try await controller.terminateProtectedProcesses()
        XCTAssertEqual(signals, [SIGSTOP, SIGTERM, SIGCONT])
        XCTAssertTrue(controller.suspended.isEmpty)

        controller.shutdown()
        XCTAssertEqual(signals, [SIGSTOP, SIGTERM, SIGCONT], "App shutdown must not resume Claude after termination")
    }

    func testFailedResumeRetainsIdentityAndRetries() throws {
        let target = record(51, path: "/usr/local/bin/claude")
        var attempts = 0
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { [target] }, identityReader: { _ in target.identity },
            signaler: { _, signal in
                if signal == SIGCONT {
                    attempts += 1
                    if attempts == 1 { errno = EPERM; return -1 }
                }
                return 0
            }
        )
        controller.apply(try observation("NL"), allowedCountryCode: "NL")
        XCTAssertEqual(controller.suspended, [target.identity])
        guard case .failed = controller.status else { return XCTFail("Failed resume must not report active") }
        controller.apply(try observation("NL"), allowedCountryCode: "NL")
        XCTAssertTrue(controller.suspended.isEmpty)
        XCTAssertEqual(attempts, 2)
        guard case .active = controller.status else { return XCTFail("Successful retry must restore active status") }
    }

    func testUnknownCountryKeepsClaudePausedUntilExplicitTrust() throws {
        let target = record(50, path: "/usr/local/bin/claude")
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { [target] }, identityReader: { _ in target.identity },
            signaler: { _, signal in signals.append(signal); return 0 }
        )
        controller.apply(try observation("NL"), allowedCountryCode: nil)
        XCTAssertEqual(signals, [SIGSTOP])
        guard case .needsAllowedCountry("NL", 1) = controller.status else {
            return XCTFail("First run must expose the observed country without resuming Claude")
        }
    }

    func testAppModelPersistsExplicitCountryAndActivatesProtection() async throws {
        let suite = "ProcessProtectionControllerTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let target = record(60, path: "/fixture/home/.local/bin/claude")
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { [target] }, identityReader: { _ in target.identity },
            signaler: { _, signal in signals.append(signal); return 0 }
        )
        let result = try EgressObservation.decode(
            Data(#"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#.utf8),
            provider: .ipWhoIS, checkedAt: Date(timeIntervalSince1970: 1)
        )
        let countryResult = try EgressObservation.decode(
            Data(#"{"ip":"203.0.113.7","country":"NL"}"#.utf8),
            provider: .ipInfo, checkedAt: Date(timeIntervalSince1970: 1)
        )
        let model = AppModel(
            defaults: defaults, startsMonitoring: false, automaticCheckDelay: 0,
            diagnosticsReader: { .notChecked }, egressReader: { provider in
                provider == .ipWhoIS ? result : countryResult
            },
            processProtection: controller
        )
        model.refreshExternalIP()
        for _ in 0..<200 {
            if case .observed = model.externalCheck { break }
            await Task.yield()
        }
        guard case .observed = model.externalCheck else { return XCTFail("Egress check did not finish") }
        XCTAssertNil(model.preferences.allowedCountryCode)
        XCTAssertEqual(signals, [SIGSTOP])

        model.trustCurrentCountry()
        XCTAssertEqual(model.preferences.allowedCountryCode, "NL")
        XCTAssertEqual(signals, [SIGSTOP, SIGCONT])
        XCTAssertEqual(model.protection, .countryConfirmed)
        XCTAssertFalse(model.protection.canSafelyLaunch)
        let stored = try XCTUnwrap(defaults.data(forKey: "armor.preferences.v1"))
        XCTAssertEqual(try JSONDecoder().decode(AppPreferences.self, from: stored).allowedCountryCode, "NL")
    }

    func testCountryDatabaseDisagreementUsesIPWhoISAndRemainsVisible() async throws {
        let suite = "ProcessProtectionControllerTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, egressReader: { provider in
            let json = provider == .ipWhoIS
                ? #"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#
                : #"{"ip":"203.0.113.7","country":"DE"}"#
            return try EgressObservation.decode(Data(json.utf8), provider: provider)
        }, processProtection: controller)
        model.checkExternalIPAfterConsent(provider: .ipInfo)
        for _ in 0..<200 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        guard case .observed(let observation) = model.externalCheck else {
            return XCTFail("Matching IPs should complete even when GeoIP databases disagree")
        }
        XCTAssertEqual(observation.provider, .ipWhoIS)
        XCTAssertEqual(observation.countryCode, "NL")
        XCTAssertEqual(model.countryComparison?.ipWhoIS, "NL")
        XCTAssertEqual(model.countryComparison?.independentCountry, "DE")
        XCTAssertEqual(model.countryComparison?.independentProvider, .ipInfo)
        XCTAssertTrue(StatusPanelContent(model: model).externalDetail.contains("геобазы расходятся"))
        model.trustCurrentCountry()
        XCTAssertEqual(model.preferences.allowedCountryCode, "NL")
        XCTAssertTrue(model.protection.isOperational)
    }

    func testExpiredLeasePausesClaudeUntilScheduledRefreshSucceeds() async throws {
        let suite = "ProcessProtectionControllerTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(
            try JSONEncoder().encode(AppPreferences(allowedCountryCode: "NL")),
            forKey: "armor.preferences.v1"
        )

        let target = record(70, path: "/fixture/home/.local/bin/claude")
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { [target] }, identityReader: { _ in target.identity },
            signaler: { _, signal in signals.append(signal); return 0 }
        )
        var date = Date(timeIntervalSince1970: 1_000)
        var requests = 0
        var scheduledRefresh: CheckedContinuation<EgressObservation, Error>?
        func result(_ provider: EgressProvider, country: String = "NL") throws -> EgressObservation {
            let json = provider == .ipWhoIS
                ? #"{"success":true,"ip":"203.0.113.7","country_code":"\#(country)"}"#
                : #"{"ip":"203.0.113.7","country":"\#(country)"}"#
            return try EgressObservation.decode(Data(json.utf8), provider: provider, checkedAt: date)
        }
        let model = AppModel(
            defaults: defaults, startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
            diagnosticsReader: { .notChecked }, egressReader: { provider in
                requests += 1
                if requests <= 2 { return try result(provider) }
                if requests == 3 {
                    return try await withCheckedThrowingContinuation { scheduledRefresh = $0 }
                }
                if requests == 4 { return try result(provider) }
                return try result(provider, country: "DE")
            },
            processProtection: controller
        )

        model.receive(NetworkSnapshot(connectivity: .available))
        for _ in 0..<200 {
            if case .observed = model.externalCheck { break }
            await Task.yield()
        }
        XCTAssertEqual(signals, [SIGSTOP, SIGCONT])
        XCTAssertEqual(model.protection, .countryConfirmed)
        XCTAssertFalse(model.protection.canSafelyLaunch)

        date.addTimeInterval(60)
        model.expireExternalCheck()
        for _ in 0..<200 {
            if scheduledRefresh != nil { break }
            await Task.yield()
        }
        XCTAssertNotNil(scheduledRefresh)
        XCTAssertEqual(signals, [SIGSTOP, SIGCONT, SIGSTOP], "Expired confirmation must pause even while a request is in flight")
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertFalse(model.protection.canSafelyLaunch)

        let continuation = try XCTUnwrap(scheduledRefresh)
        continuation.resume(returning: try result(.ipWhoIS))
        for _ in 0..<200 {
            if case .observed = model.externalCheck { break }
            await Task.yield()
        }
        XCTAssertEqual(requests, 4)
        XCTAssertEqual(signals, [SIGSTOP, SIGCONT, SIGSTOP, SIGCONT])
        XCTAssertEqual(model.protection, .countryConfirmed)
        XCTAssertFalse(model.protection.canSafelyLaunch)

        date.addTimeInterval(60)
        model.expireExternalCheck()
        for _ in 0..<200 {
            if requests == 6, !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        XCTAssertEqual(requests, 6)
        XCTAssertEqual(signals, [SIGSTOP, SIGCONT, SIGSTOP, SIGCONT, SIGSTOP], "A mismatched scheduled result must still pause Claude")
        XCTAssertFalse(model.protection.canSafelyLaunch)
    }

    func testDisagreeingProvidersNeverActivateProtection() async throws {
        let suite = "ProcessProtectionControllerTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(
            try JSONEncoder().encode(AppPreferences(allowedCountryCode: "NL")),
            forKey: "armor.preferences.v1"
        )
        let target = record(80, path: "/fixture/home/.local/bin/claude")
        var signals: [Int32] = []
        let controller = ProcessProtectionController(
            automaticallyMonitor: false,
            processReader: { [target] }, identityReader: { _ in target.identity },
            signaler: { _, signal in signals.append(signal); return 0 }
        )
        let model = AppModel(
            defaults: defaults, startsMonitoring: false, automaticCheckDelay: 0,
            diagnosticsReader: { .notChecked }, egressReader: { provider in
                let json = provider == .ipWhoIS
                    ? #"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#
                    : #"{"ip":"203.0.113.8","country":"NL"}"#
                return try EgressObservation.decode(Data(json.utf8), provider: provider)
            },
            processProtection: controller
        )
        model.refreshExternalIP()
        for _ in 0..<200 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        guard case .failed(let message) = model.externalCheck else {
            return XCTFail("Provider disagreement must fail the check")
        }
        XCTAssertTrue(message.contains("разный внешний IP"))
        XCTAssertEqual(signals, [SIGSTOP])
        XCTAssertFalse(model.protection.canSafelyLaunch)
    }
}
