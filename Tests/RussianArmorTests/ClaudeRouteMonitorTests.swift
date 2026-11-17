import ArmorCore
import Darwin
import Foundation
import XCTest
@testable import RussianArmor

private actor RouteGate {
    private(set) var calls = 0
    private(set) var targets: Set<TrafficProcess.ID> = []
    private var pending: [Int: CheckedContinuation<ClaudeRouteSnapshot, Error>] = [:]
    func read(_ targets: Set<TrafficProcess.ID>) async throws -> ClaudeRouteSnapshot {
        calls += 1
        self.targets = targets
        let call = calls
        return try await withCheckedThrowingContinuation { pending[call] = $0 }
    }
    func resolve(_ call: Int, _ result: Result<ClaudeRouteSnapshot, Error>) {
        pending.removeValue(forKey: call)?.resume(with: result)
    }
}

private actor EgressRefreshGate {
    private var holding = false
    private var pending: CheckedContinuation<Void, Never>?
    private(set) var calls = 0

    func hold() { holding = true }
    func release() {
        holding = false
        pending?.resume()
        pending = nil
    }
    func read(_ provider: EgressProvider) async throws -> EgressObservation {
        calls += 1
        if holding { await withCheckedContinuation { pending = $0 } }
        let json = provider == .ipWhoIS
            ? #"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#
            : #"{"ip":"203.0.113.7","country":"NL"}"#
        return try EgressObservation.decode(Data(json.utf8), provider: provider)
    }
}

@MainActor
final class ClaudeRouteMonitorTests: XCTestCase {
    private func wait(_ condition: () async -> Bool) async {
        for _ in 0..<1000 {
            if await condition() { return }
            await Task.yield()
        }
        XCTFail("Condition did not settle")
    }

    private func fixture(at date: Date = Date(), tunnel: Bool = true) -> ClaudeRouteSnapshot {
        let connection = TrafficConnection(
            process: .init(id: .init(pid: 900001, startSeconds: 1, startMicroseconds: 2), name: "claude"),
            socketGeneration: 1, descriptor: 4, transport: .tcp,
            local: .init(address: tunnel ? "10.8.0.2" : "192.168.1.2", port: 50100, version: .v4),
            remote: .init(address: "203.0.113.77", port: 443, version: .v4), state: "Установлено")
        let interface = tunnel ? "utun4" : "en0"
        return ClaudeRouteSnapshot(routes: [.init(connection: connection, sourceInterfaces: [interface], routeInterface: interface)], capturedAt: date)
    }

    func testRefreshAndSleepRejectOldGenerationAndClearEndpointsImmediately() async {
        let gate = RouteGate()
        let monitor = ClaudeRouteMonitor(identities: { [] }, reader: { try await gate.read($0) })
        monitor.start()
        await wait { await gate.calls == 1 }
        monitor.refresh()
        await wait { await gate.calls == 2 }
        await gate.resolve(1, .success(fixture()))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(monitor.state, .checking)
        await gate.resolve(2, .success(fixture()))
        await wait { monitor.state.snapshot != nil }
        monitor.refresh()
        XCTAssertNil(monitor.state.snapshot)
        await wait { await gate.calls == 3 }
        monitor.prepareForSleep()
        await gate.resolve(3, .success(fixture()))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(monitor.state, .sleeping)
        XCTAssertNotNil(monitor.pauseReason(vpnLocation: .thisMac))
        monitor.resumeAfterWake()
        await wait { await gate.calls == 4 }
        await gate.resolve(4, .failure(TrafficReadError.unavailable))
        await wait { monitor.state == .failed }
        XCTAssertNil(monitor.state.snapshot)
        monitor.prepareForSleep()
    }

    func testLeaseExpiresWhileNextReadHangsAndLateOldSampleCannotRenewIt() async {
        let gate = RouteGate()
        var now = Date(timeIntervalSince1970: 1000)
        let monitor = ClaudeRouteMonitor(interval: 1, now: { now }, identities: { [] }, reader: { try await gate.read($0) })
        monitor.start()
        await wait { await gate.calls == 1 }
        await gate.resolve(1, .success(fixture(at: now)))
        await wait { await gate.calls == 2 }
        XCTAssertNil(monitor.pauseReason(vpnLocation: .thisMac))
        now += ClaudeRouteMonitor.maximumAge
        // The permission guard rejects stale data even before the expiry timer.
        XCTAssertNotNil(monitor.pauseReason(vpnLocation: .thisMac))
        monitor.expire()
        XCTAssertEqual(monitor.state, .failed)
        await gate.resolve(2, .success(fixture(at: now.addingTimeInterval(-6))))
        await wait { await gate.calls == 3 }
        XCTAssertEqual(monitor.state, .failed)
        monitor.prepareForSleep()
        await gate.resolve(3, .success(fixture(at: now)))
    }

    func testClockRollbackInvalidatesSample() async {
        var now = Date(timeIntervalSince1970: 1000)
        let sample = fixture(at: now)
        let monitor = ClaudeRouteMonitor(now: { now }, identities: { [] }, reader: { _ in sample })
        monitor.start()
        await wait { monitor.state.snapshot != nil }
        now -= 1
        monitor.expire()
        XCTAssertEqual(monitor.state, .failed)
        monitor.prepareForSleep()
    }

    func testRouteUpdatesPreserveUnexpiredEgressLeaseDuringPlannedRefresh() async throws {
        let suite = "ClaudeRoutesLeaseTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(try JSONEncoder().encode(AppPreferences(vpnLocation: .thisMac, allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
        let gate = EgressRefreshGate()
        let sample = fixture()
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { try await gate.read($0) }, processProtection: controller,
                             claudeRouteReader: { _ in sample })
        model.refreshExternalIP()
        await wait { model.protection.isOperational }
        await gate.hold()
        model.refreshExternalIP()
        await wait { await gate.calls == 3 }
        XCTAssertTrue(model.externalCheck.isChecking)
        // Simulate the next successful route poll while the refresh is pending.
        model.claudeRoutes.refresh()
        await wait { model.claudeRoutes.state.snapshot != nil }
        XCTAssertTrue(model.externalCheck.isChecking)
        XCTAssertTrue(model.protection.isOperational, "A valid egress lease must survive route polls during its refresh")
        await gate.release()
        await wait { !model.externalCheck.isChecking }
        model.prepareForSleep()
    }

    func testRoutesGateRealPauseResumeAndCannotBeOverriddenByEgressSuccess() async throws {
        let suite = "ClaudeRoutesPolicyTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(try JSONEncoder().encode(AppPreferences(vpnLocation: .thisMac, allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
        let identity = ProtectedProcessIdentity(pid: 900001, startSeconds: 1, startMicroseconds: 2)
        let target = ProtectedProcessRecord(identity: identity, parentPID: 1, executablePath: "/fixture/claude",
                                            processName: "claude", isClaudeDesktopRoot: false, isClaudeCodeInterpreter: false)
        var signals: [Int32] = []
        var stopped = false
        let controller = ProcessProtectionController(
            automaticallyMonitor: false, processReader: { [target] }, identityReader: { _ in identity },
            signaler: { _, signal in signals.append(signal); stopped = signal == SIGSTOP; return 0 },
            isStopped: { _ in stopped }
        )
        let gate = RouteGate()
        let model = AppModel(defaults: defaults, startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: { provider in
            let json = provider == .ipWhoIS
                ? #"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#
                : #"{"ip":"203.0.113.7","country":"NL"}"#
            return try EgressObservation.decode(Data(json.utf8), provider: provider)
        }, processProtection: controller, claudeRouteReader: { try await gate.read($0) })
        model.refreshExternalIP()
        await wait { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        await wait { await gate.calls == 1 }
        let requested = await gate.targets
        XCTAssertEqual(requested, [TrafficProcess.ID(pid: identity.pid, startSeconds: 1, startMicroseconds: 2)])
        await gate.resolve(1, .success(fixture(tunnel: false)))
        await wait { model.claudeRoutes.state.snapshot != nil }
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertTrue(stopped)
        XCTAssertFalse(signals.contains(SIGCONT))

        // A second successful external-IP result cannot bypass the bad socket.
        model.refreshExternalIP()
        await wait { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        model.claudeRoutes.refresh()
        await wait { await gate.calls == 2 }
        await gate.resolve(2, .success(fixture()))
        await wait { model.protection.isOperational }
        XCTAssertTrue(signals.contains(SIGCONT))
        XCTAssertFalse(stopped)

        for data in (defaults.persistentDomain(forName: suite) ?? [:]).values.compactMap({ $0 as? Data }) {
            let text = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(text.contains("203.0.113.77"))
            XCTAssertFalse(text.contains("10.8.0.2"))
        }
        model.prepareForSleep()
        XCTAssertTrue(stopped)
        XCTAssertNil(model.claudeRoutes.state.snapshot)
    }
}
