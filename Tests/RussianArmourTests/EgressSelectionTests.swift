import Foundation
import XCTest
import ArmourCore
@testable import RussianArmour

@MainActor
final class EgressSelectionTests: XCTestCase {
    private func defaults() -> (UserDefaults, String) {
        let name = "EgressSelectionTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.set(try! JSONEncoder().encode(AppPreferences(automaticIPChecks: false)), forKey: "armour.preferences.v1")
        return (defaults, name)
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<100 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("External check did not settle")
    }

    func testOnlyExplicitlySelectedProviderIsRead() async throws {
        let (storage, name) = defaults()
        defer { storage.removePersistentDomain(forName: name) }
        var requests: [EgressProvider] = []
        let response = try EgressObservation.decode(
            Data(#"{"success":true,"ip":"2001:db8::7","country_code":"NL"}"#.utf8), provider: .ipWhoIS
        )
        let model = AppModel(defaults: storage, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            return response
        })
        XCTAssertTrue(requests.isEmpty)
        model.checkExternalIPAfterConsent(provider: .ipWhoIS)
        model.checkExternalIPAfterConsent(provider: .countryIS)
        await settle(model)
        XCTAssertEqual(requests, [.ipWhoIS])
        XCTAssertEqual(model.externalProvider, .ipWhoIS)
        XCTAssertEqual(model.externalCheck, .observed(response))
        for data in storage.dictionaryRepresentation().values.compactMap({ $0 as? Data }) {
            XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(response.ip))
        }
        XCTAssertEqual(model.protection, .notConfigured)
    }

    func testTLSFailureDoesNotAutomaticallyTryAlternativeOrLoseItsReason() async {
        let (storage, name) = defaults()
        defer { storage.removePersistentDomain(forName: name) }
        var requests: [EgressProvider] = []
        let error = NSError(domain: NSURLErrorDomain, code: -1200, userInfo: [NSLocalizedDescriptionKey: "private-token 203.0.113.99"])
        let model = AppModel(defaults: storage, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            throw error
        })
        model.checkExternalIPAfterConsent(provider: .countryIS)
        await settle(model)
        let failed = model.externalCheck
        guard case .failed(let message) = failed else { return XCTFail("TLS error was not exposed") }
        XCTAssertTrue(message.contains("TLS"))
        XCTAssertTrue(message.contains("−1200"))
        model.refresh()
        model.preferences.vpnLocation = .router
        model.prepareForSleep()
        model.resumeAfterWake()
        await Task.yield()
        XCTAssertEqual(requests, [.countryIS])
        XCTAssertEqual(model.externalCheck, failed)
        for data in storage.dictionaryRepresentation().values.compactMap({ $0 as? Data }) {
            let persisted = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(persisted.contains("203.0.113.99"))
            XCTAssertFalse(persisted.contains("private-token"))
            XCTAssertFalse(persisted.contains("TLS"))
        }
    }

    func testRetryUsesOnlyNewlyConfirmedProvider() async throws {
        let (storage, name) = defaults()
        defer { storage.removePersistentDomain(forName: name) }
        var requests: [EgressProvider] = []
        let response = try EgressObservation.decode(
            Data(#"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#.utf8), provider: .ipWhoIS
        )
        let model = AppModel(defaults: storage, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: {
            requests.append($0)
            if $0 == .countryIS { throw URLError(.secureConnectionFailed) }
            return response
        })
        model.checkExternalIPAfterConsent(provider: .countryIS)
        await settle(model)
        XCTAssertEqual(requests, [.countryIS])
        model.checkExternalIPAfterConsent(provider: .ipWhoIS)
        await settle(model)
        XCTAssertEqual(requests, [.countryIS, .ipWhoIS])
        XCTAssertEqual(model.externalCheck, .observed(response))
    }

    func testMismatchedProviderCannotBeReportedAsSuccess() async throws {
        let (storage, name) = defaults()
        defer { storage.removePersistentDomain(forName: name) }
        let countryResponse = try EgressObservation.decode(Data(#"{"ip":"203.0.113.7","country":"NL"}"#.utf8))
        let model = AppModel(defaults: storage, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in countryResponse })
        model.checkExternalIPAfterConsent(provider: .ipWhoIS)
        await settle(model)
        guard case .failed = model.externalCheck else { return XCTFail("Wrong provider attributed as success") }
    }

    func testCancelledFirstProviderCannotReplaceNewProviderResult() async throws {
        let (storage, name) = defaults()
        defer { storage.removePersistentDomain(forName: name) }
        var pending: CheckedContinuation<EgressObservation, Error>?
        let oldResponse = try EgressObservation.decode(Data(#"{"ip":"203.0.113.1","country":"NL"}"#.utf8))
        let newResponse = try EgressObservation.decode(
            Data(#"{"success":true,"ip":"203.0.113.2","country_code":"DE"}"#.utf8), provider: .ipWhoIS
        )
        let model = AppModel(defaults: storage, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: {
            if $0 == .countryIS { return try await withCheckedThrowingContinuation { pending = $0 } }
            return newResponse
        })
        model.checkExternalIPAfterConsent(provider: .countryIS)
        for _ in 0..<100 {
            if pending != nil { break }
            await Task.yield()
        }
        guard let continuation = pending else { return XCTFail("First reader did not start") }
        model.refresh()
        model.checkExternalIPAfterConsent(provider: .ipWhoIS)
        await settle(model)
        continuation.resume(returning: oldResponse)
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(model.externalProvider, .ipWhoIS)
        XCTAssertEqual(model.externalCheck, .observed(newResponse))
    }
}
