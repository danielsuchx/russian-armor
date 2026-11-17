import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

private actor TrafficGate {
    private(set) var calls = 0
    private var pending: [Int: CheckedContinuation<TrafficSnapshot, Error>] = [:]
    func read() async throws -> TrafficSnapshot {
        calls += 1
        let id = calls
        return try await withCheckedThrowingContinuation { pending[id] = $0 }
    }
    func resolve(_ id: Int, with result: Result<TrafficSnapshot, Error>) {
        pending.removeValue(forKey: id)?.resume(with: result)
    }
}

@MainActor
final class TrafficMonitorTests: XCTestCase {
    private func fixture(_ address: String = "203.0.113.7") -> TrafficSnapshot {
        TrafficSnapshot(connections: [TrafficConnection(
            process: .init(id: .init(pid: 42, startSeconds: 100, startMicroseconds: 1), name: "Fixture"),
            socketGeneration: 1, descriptor: 7, transport: .tcp,
            local: .init(address: "192.0.2.5", port: 51000, version: .v4),
            remote: .init(address: address, port: 443, version: .v4), state: "Установлено")])
    }

    private func waitForCalls(_ count: Int, gate: TrafficGate) async {
        for _ in 0..<1000 {
            if await gate.calls >= count { return }
            await Task.yield()
        }
        XCTFail("Expected reader invocation \(count)")
    }

    private func waitForSnapshot(_ monitor: TrafficMonitor) async {
        for _ in 0..<1000 {
            if monitor.state.snapshot != nil { return }
            await Task.yield()
        }
        XCTFail("Snapshot never arrived")
    }

    func testOffNeverReadsAndStartIsIdempotent() async {
        let gate = TrafficGate()
        let monitor = TrafficMonitor(reader: { try await gate.read() })
        monitor.refresh()
        monitor.resumeAfterWake()
        for _ in 0..<10 { await Task.yield() }
        let before = await gate.calls
        XCTAssertEqual(before, 0)
        XCTAssertEqual(monitor.state, .off)
        monitor.start()
        monitor.start()
        await waitForCalls(1, gate: gate)
        let calls = await gate.calls
        XCTAssertEqual(calls, 1)
        await gate.resolve(1, with: .success(fixture()))
        await waitForSnapshot(monitor)
        monitor.stop()
        XCTAssertEqual(monitor.state, .off)
        XCTAssertFalse(monitor.isEnabled)
    }

    func testStopRejectsLateResponse() async {
        let gate = TrafficGate()
        let monitor = TrafficMonitor(reader: { try await gate.read() })
        monitor.start()
        await waitForCalls(1, gate: gate)
        monitor.stop()
        await gate.resolve(1, with: .success(fixture()))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(monitor.state, .off)
        XCTAssertNil(monitor.state.snapshot)
    }

    func testRefreshDiscardsPreviousGeneration() async {
        let gate = TrafficGate()
        let monitor = TrafficMonitor(reader: { try await gate.read() })
        defer { monitor.stop() }
        monitor.start()
        await waitForCalls(1, gate: gate)
        monitor.refresh()
        await waitForCalls(2, gate: gate)
        await gate.resolve(1, with: .success(fixture()))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(monitor.state, .sampling)
        await gate.resolve(2, with: .success(fixture("203.0.113.8")))
        await waitForSnapshot(monitor)
        XCTAssertEqual(monitor.state.snapshot?.connections.first?.remote.address, "203.0.113.8")
    }

    func testSleepClearsAndWakeResumesOnlyIfEnabled() async {
        let gate = TrafficGate()
        let monitor = TrafficMonitor(reader: { try await gate.read() })
        monitor.start()
        await waitForCalls(1, gate: gate)
        monitor.prepareForSleep()
        XCTAssertEqual(monitor.state, .sleeping)
        await gate.resolve(1, with: .success(fixture()))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertNil(monitor.state.snapshot)
        monitor.resumeAfterWake()
        await waitForCalls(2, gate: gate)
        monitor.prepareForSleep()
        monitor.stop()
        monitor.resumeAfterWake()
        await gate.resolve(2, with: .success(fixture()))
        for _ in 0..<20 { await Task.yield() }
        let calls = await gate.calls
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(monitor.state, .off)
    }

    func testFailedRefreshRemovesOldAddresses() async {
        let gate = TrafficGate()
        let monitor = TrafficMonitor(reader: { try await gate.read() })
        defer { monitor.stop() }
        monitor.start()
        await waitForCalls(1, gate: gate)
        await gate.resolve(1, with: .success(fixture()))
        await waitForSnapshot(monitor)
        monitor.refresh()
        XCTAssertNil(monitor.state.snapshot)
        await waitForCalls(2, gate: gate)
        await gate.resolve(2, with: .failure(TrafficReadError.unavailable))
        for _ in 0..<1000 {
            if case .failed = monitor.state { break }
            await Task.yield()
        }
        guard case .failed = monitor.state else { return XCTFail("Failure not exposed") }
        XCTAssertNil(monitor.state.snapshot)
    }

    func testVPNAndTunnelChangesDiscardTheOldSnapshot() async {
        let suite = "TrafficInvalidationTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let gate = TrafficGate()
        var tunnels: [String] = []
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: {
            LocalDiagnosticsSnapshot(tunnels: .observed(tunnels), claudeDesktop: .notRunning, checkedAt: Date())
        }, trafficReader: { try await gate.read() })
        defer { model.traffic.stop() }
        model.traffic.start()
        await waitForCalls(1, gate: gate)
        await gate.resolve(1, with: .success(fixture()))
        await waitForSnapshot(model.traffic)
        model.preferences.vpnLocation = .router
        XCTAssertEqual(model.traffic.state, .sampling)
        await waitForCalls(2, gate: gate)
        await gate.resolve(2, with: .success(fixture()))
        await waitForSnapshot(model.traffic)
        tunnels = ["utun9"]
        model.refreshDiagnostics()
        XCTAssertEqual(model.traffic.state, .sampling)
        await waitForCalls(3, gate: gate)
        await gate.resolve(3, with: .success(fixture()))
        await waitForSnapshot(model.traffic)
        XCTAssertEqual(model.protection, .notConfigured)
        XCTAssertEqual(model.externalCheck, .notChecked)
    }

    func testAppModelNeverPersistsEndpointsOrEnablement() async throws {
        let suite = "TrafficPrivacyTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let snapshot = fixture()
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             trafficReader: { snapshot })
        XCTAssertEqual(model.traffic.state, .off)
        model.preferences.vpnLocation = .router
        XCTAssertEqual(model.traffic.state, .off)
        model.traffic.start()
        defer { model.traffic.stop() }
        await waitForSnapshot(model.traffic)
        for data in (defaults.persistentDomain(forName: suite) ?? [:]).values.compactMap({ $0 as? Data }) {
            let text = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(text.contains("203.0.113.7"))
            XCTAssertFalse(text.contains("192.0.2.5"))
        }
        XCTAssertFalse(model.journal.events.contains { $0.detail.contains("203.0.113.7") })
        XCTAssertEqual(model.protection, .notConfigured)
        model.prepareForSleep()
        XCTAssertEqual(model.traffic.state, .sleeping)
        model.resumeAfterWake()
        await waitForSnapshot(model.traffic)
        let restored = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked })
        XCTAssertEqual(restored.traffic.state, .off)
        XCTAssertFalse(restored.traffic.isEnabled)
    }
}
