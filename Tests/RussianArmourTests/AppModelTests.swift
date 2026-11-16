import Foundation
import XCTest
import ArmourCore
@testable import RussianArmour

@MainActor
final class AppModelTests: XCTestCase {
    private func isolatedDefaults() -> (UserDefaults, String) {
        let name = "RussianArmourTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.set(try! JSONEncoder().encode(AppPreferences(automaticIPChecks: false)), forKey: "armour.preferences.v1")
        return (defaults, name)
    }

    private func fixture() throws -> EgressObservation {
        try EgressObservation.decode(Data(#"{"ip":"203.0.113.7","country":"NL"}"#.utf8))
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<100 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("External check did not settle")
    }

    func testStartupAndLocalRefreshNeverContactProvider() async {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        var requests = 0
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: {
            LocalDiagnosticsSnapshot(tunnels: .observed([]), claudeDesktop: .notRunning, checkedAt: Date())
        }, egressReader: { _ in
            requests += 1
            throw EgressError.invalidResponse
        })
        model.refresh()
        model.preferences.vpnLocation = .router
        model.refreshDiagnostics()
        await Task.yield()
        XCTAssertEqual(requests, 0)
        XCTAssertEqual(model.externalCheck, .notChecked)
        XCTAssertEqual(model.diagnostics.tunnels, .observed([]))
        XCTAssertEqual(model.protection, .notConfigured)
    }

    func testConsentedResponseIsNotSavedToDefaultsOrHistory() async throws {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        let response = try fixture()
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in response })
        model.checkExternalIPAfterConsent()
        await settle(model)
        XCTAssertEqual(model.externalCheck, .observed(response))
        let stored = defaults.dictionaryRepresentation().values.compactMap { $0 as? Data }
        for data in stored {
            XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(response.ip))
        }
        XCTAssertFalse(model.journal.events.contains { $0.detail.contains(response.ip) || $0.title.contains(response.ip) })
        XCTAssertEqual(model.protection, .notConfigured)
        let restored = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked })
        XCTAssertEqual(restored.externalCheck, .notChecked)
    }

    func testChangingVPNLocationInvalidatesOldResult() async throws {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        let response = try fixture()
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in response })
        model.checkExternalIPAfterConsent()
        await settle(model)
        model.preferences.vpnLocation = .router
        guard case .needsRecheck = model.externalCheck else { return XCTFail("Old result remained current") }
    }

    func testResultExpiresWithoutAutomaticRequest() async throws {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        let response = try fixture()
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in response })
        model.checkExternalIPAfterConsent()
        await settle(model)
        model.expireExternalCheck(now: response.checkedAt.addingTimeInterval(61))
        guard case .needsRecheck = model.externalCheck else { return XCTFail("Expired result remained current") }
    }

    func testFailedCheckDoesNotClaimProtection() async {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in throw EgressError.invalidResponse })
        model.checkExternalIPAfterConsent()
        await settle(model)
        guard case .failed = model.externalCheck else { return XCTFail("Failure not exposed") }
        XCTAssertFalse(model.protection.canSafelyLaunch)
    }

    func testSleepInvalidatesObservationsAndStopsLocalPolling() async {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        var reads = 0
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: {
            reads += 1
            return LocalDiagnosticsSnapshot(tunnels: .observed(["utun1"]), claudeDesktop: .running, checkedAt: Date())
        })
        model.prepareForSleep()
        let before = reads
        model.refreshDiagnostics()
        XCTAssertEqual(reads, before)
        XCTAssertEqual(model.diagnostics, .notChecked)
        model.resumeAfterWake()
        XCTAssertGreaterThan(reads, before)
        XCTAssertEqual(model.protection, .notConfigured)
    }

    func testLateResponseAfterSleepCannotRestoreOldIP() async throws {
        let (defaults, name) = isolatedDefaults()
        defer { defaults.removePersistentDomain(forName: name) }
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in
            try await withCheckedThrowingContinuation { pending = $0 }
        })
        model.checkExternalIPAfterConsent()
        for _ in 0..<100 {
            if pending != nil { break }
            await Task.yield()
        }
        guard let continuation = pending else { return XCTFail("Request never started") }
        model.prepareForSleep()
        continuation.resume(returning: try fixture())
        for _ in 0..<10 { await Task.yield() }
        guard case .needsRecheck = model.externalCheck else { return XCTFail("Late response restored stale IP") }
    }
}
