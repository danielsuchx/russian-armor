import Foundation
import XCTest
import ArmourCore
@testable import RussianArmour

@MainActor
final class AutomaticEgressTests: XCTestCase {
    private var domains: [String] = []

    override func tearDown() {
        for name in domains { UserDefaults(suiteName: name)?.removePersistentDomain(forName: name) }
        super.tearDown()
    }

    private func storage(_ preferences: AppPreferences = AppPreferences()) throws -> UserDefaults {
        let name = "AutomaticEgressTests.\(UUID().uuidString)"
        domains.append(name)
        let defaults = UserDefaults(suiteName: name)!
        defaults.set(try JSONEncoder().encode(preferences), forKey: "armour.preferences.v1")
        return defaults
    }

    private func response(_ provider: EgressProvider, at date: Date) throws -> EgressObservation {
        let json = provider == .countryIS
            ? #"{"ip":"203.0.113.7","country":"NL"}"#
            : #"{"success":true,"ip":"203.0.113.8","country_code":"DE"}"#
        return try EgressObservation.decode(Data(json.utf8), provider: provider, checkedAt: date)
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<200 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("External check did not settle")
    }

    private func waitForRequest(_ predicate: () -> Bool) async {
        for _ in 0..<200 {
            if predicate() { return }
            await Task.yield()
        }
        XCTFail("Reader did not start")
    }

    func testFirstAvailableNetworkAutomaticallyUsesIPWhoISAndDoesNotPersistIP() async throws {
        let defaults = try storage()
        let date = Date()
        var requests: [EgressProvider] = []
        let model = AppModel(defaults: defaults, startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            return try self.response($0, at: date)
        })
        XCTAssertTrue(requests.isEmpty, "Unknown connectivity must wait for NWPathMonitor")
        model.receive(NetworkSnapshot(connectivity: .available, availableInterfaces: ["en0"]))
        await settle(model)
        XCTAssertEqual(requests, [.ipWhoIS])
        let observation = try response(.ipWhoIS, at: date)
        XCTAssertEqual(model.externalCheck, .observed(observation))
        for _ in 0..<5 {
            model.receive(NetworkSnapshot(connectivity: .available, availableInterfaces: ["en0"]))
            model.refreshDiagnostics()
        }
        await Task.yield()
        XCTAssertEqual(requests, [.ipWhoIS], "Menu and local polling must not cause extra requests")
        XCTAssertFalse(model.journal.events.contains { $0.title == "Внешний выход проверен" }, "Periodic checks must not flood history")
        for data in defaults.dictionaryRepresentation().values.compactMap({ $0 as? Data }) {
            let text = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(text.contains(observation.ip))
            XCTAssertFalse(text.contains("countryCode"))
        }
        XCTAssertEqual(model.protection, .notConfigured)
    }

    func testSuccessfulResultRefreshesAfterOneMinuteWithoutUserAction() async throws {
        var date = Date()
        var requests = 0
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests += 1
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        date.addTimeInterval(59)
        model.refreshDiagnostics()
        await Task.yield()
        XCTAssertEqual(requests, 1)
        date.addTimeInterval(1)
        model.refreshDiagnostics()
        XCTAssertTrue(model.externalCheck.isChecking)
        await settle(model)
        XCTAssertEqual(requests, 2)
        XCTAssertEqual(model.externalCheck, .observed(try response(.ipWhoIS, at: date)))
    }

    func testFailureRetriesSameProviderAfterOneMinuteAndNeverFallsBack() async throws {
        var date = Date()
        var requests: [EgressProvider] = []
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            throw URLError(.secureConnectionFailed)
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        guard case .failed(let reason) = model.externalCheck else { return XCTFail("Failure not exposed") }
        XCTAssertTrue(reason.contains("TLS"))
        for _ in 0..<5 { model.refreshDiagnostics() }
        await Task.yield()
        XCTAssertEqual(requests, [.ipWhoIS])
        date.addTimeInterval(59)
        model.refreshDiagnostics()
        await Task.yield()
        XCTAssertEqual(requests, [.ipWhoIS])
        date.addTimeInterval(1)
        model.refreshDiagnostics()
        await settle(model)
        XCTAssertEqual(requests, [.ipWhoIS, .ipWhoIS])
        XCTAssertEqual(model.externalCheck, .failed(reason))
    }

    func testDisabledPolicyStaysDisabledAcrossNetworkWakeAndRestartButAllowsManualCheck() async throws {
        let defaults = try storage(AppPreferences(automaticIPChecks: false, egressProvider: .countryIS))
        let date = Date()
        var requests: [EgressProvider] = []
        let model = AppModel(defaults: defaults, startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        model.prepareForSleep()
        model.resumeAfterWake()
        model.receive(NetworkSnapshot(connectivity: .available))
        model.preferences.vpnLocation = .router
        model.refreshDiagnostics()
        await Task.yield()
        XCTAssertTrue(requests.isEmpty)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertEqual(requests, [.countryIS])
        let restored = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked })
        XCTAssertFalse(restored.preferences.automaticIPChecks)
        XCTAssertEqual(restored.preferences.egressProvider, .countryIS)
        XCTAssertEqual(restored.externalCheck, .notChecked)
    }

    func testSleepDiscardsLateResponseAndWakeStartsFreshRequest() async throws {
        let date = Date()
        var requests = 0
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: try storage(), startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests += 1
            if requests == 1 { return try await withCheckedThrowingContinuation { pending = $0 } }
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        await waitForRequest { pending != nil }
        let continuation = try XCTUnwrap(pending)
        model.prepareForSleep()
        continuation.resume(returning: try response(.ipWhoIS, at: date))
        model.refreshDiagnostics()
        model.receive(NetworkSnapshot(connectivity: .available))
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(requests, 1)
        guard case .needsRecheck = model.externalCheck else { return XCTFail("Sleep restored an old IP") }
        model.resumeAfterWake()
        await Task.yield()
        XCTAssertEqual(requests, 1, "Wake must wait for a fresh path update")
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        XCTAssertEqual(requests, 2)
        XCTAssertEqual(model.externalCheck, .observed(try response(.ipWhoIS, at: date)))
    }

    func testOfflineCancelsPendingRequestAndReconnectChecksAgain() async throws {
        let date = Date()
        var requests = 0
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: try storage(), startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests += 1
            if requests == 1 { return try await withCheckedThrowingContinuation { pending = $0 } }
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .unavailable))
        await Task.yield()
        XCTAssertEqual(requests, 0)
        model.receive(NetworkSnapshot(connectivity: .available))
        await waitForRequest { pending != nil }
        let continuation = try XCTUnwrap(pending)
        model.receive(NetworkSnapshot(connectivity: .unavailable))
        continuation.resume(returning: try response(.ipWhoIS, at: date))
        for _ in 0..<10 { await Task.yield() }
        guard case .needsRecheck = model.externalCheck else { return XCTFail("Offline response restored old IP") }
        model.refreshDiagnostics()
        XCTAssertEqual(requests, 1)
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        XCTAssertEqual(requests, 2)
    }

    func testProviderChangeRejectsLateResponseAndPersistsOnlyNewSelection() async throws {
        let defaults = try storage()
        let date = Date()
        var requests: [EgressProvider] = []
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: defaults, startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            if $0 == .ipWhoIS { return try await withCheckedThrowingContinuation { pending = $0 } }
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        await waitForRequest { pending != nil }
        let continuation = try XCTUnwrap(pending)
        model.preferences.egressProvider = .countryIS
        await settle(model)
        continuation.resume(returning: try response(.ipWhoIS, at: date))
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(requests, [.ipWhoIS, .countryIS])
        XCTAssertEqual(model.externalCheck, .observed(try response(.countryIS, at: date)))
        XCTAssertEqual(model.externalProvider, .countryIS)
        let restored = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked })
        XCTAssertEqual(restored.preferences.egressProvider, .countryIS)
        XCTAssertTrue(restored.preferences.automaticIPChecks)
        XCTAssertEqual(restored.externalCheck, .notChecked)
    }

    func testDisablingDuringRequestRejectsLateResponseAndReenablingChecksImmediately() async throws {
        let date = Date()
        var requests = 0
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: try storage(), startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests += 1
            if requests == 1 { return try await withCheckedThrowingContinuation { pending = $0 } }
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        await waitForRequest { pending != nil }
        let continuation = try XCTUnwrap(pending)
        model.preferences.automaticIPChecks = false
        continuation.resume(returning: try response(.ipWhoIS, at: date))
        for _ in 0..<10 { await Task.yield() }
        model.refreshDiagnostics()
        XCTAssertEqual(requests, 1)
        XCTAssertEqual(model.externalCheck, .notChecked)
        model.preferences.automaticIPChecks = true
        await settle(model)
        XCTAssertEqual(requests, 2)
    }

    func testDisablingDuringDebouncePreventsEvenTheFirstRequest() async throws {
        var requests = 0
        let model = AppModel(defaults: try storage(), startsMonitoring: false,
                             diagnosticsReader: { .notChecked }, egressReader: { _ in
            requests += 1
            throw EgressError.invalidResponse
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        XCTAssertTrue(model.externalCheck.isChecking)
        model.preferences.automaticIPChecks = false
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(requests, 0)
        XCTAssertEqual(model.externalCheck, .notChecked)
    }

    func testRapidPathChangesCoalesceAndTunnelChangeRechecks() async throws {
        var tunnels = TunnelObservation.observed([])
        let date = Date()
        var requests = 0
        let model = AppModel(defaults: try storage(), startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: {
            LocalDiagnosticsSnapshot(tunnels: tunnels, claudeDesktop: .notRunning, checkedAt: date)
        }, egressReader: {
            requests += 1
            return try self.response($0, at: date)
        })
        model.receive(NetworkSnapshot(connectivity: .available, availableInterfaces: ["en0"]))
        model.receive(NetworkSnapshot(connectivity: .available, availableInterfaces: ["en1"]))
        model.receive(NetworkSnapshot(connectivity: .available, availableInterfaces: ["en2"]))
        await settle(model)
        XCTAssertEqual(requests, 1)
        tunnels = .observed(["utun3"])
        model.refreshDiagnostics()
        await settle(model)
        XCTAssertEqual(requests, 2)
        model.preferences.vpnLocation = .router
        await settle(model)
        XCTAssertEqual(requests, 3)
    }

    func testLongRunningRequestNeverOverlapsPeriodicOrManualRefresh() async throws {
        var date = Date()
        var requests = 0
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: { _ in
            requests += 1
            return try await withCheckedThrowingContinuation { pending = $0 }
        })
        model.receive(NetworkSnapshot(connectivity: .available))
        await waitForRequest { pending != nil }
        let continuation = try XCTUnwrap(pending)
        date.addTimeInterval(120)
        for _ in 0..<5 { model.refreshDiagnostics() }
        model.refreshExternalIP()
        await Task.yield()
        XCTAssertEqual(requests, 1)
        continuation.resume(returning: try response(.ipWhoIS, at: date))
        await settle(model)
        XCTAssertEqual(model.externalCheck, .observed(try response(.ipWhoIS, at: date)))
    }
}
