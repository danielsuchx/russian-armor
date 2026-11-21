import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class EgressFallbackTests: XCTestCase {
    private func defaults(strictRules: Bool = false) throws -> UserDefaults {
        let suite = "EgressFallback.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        let preferences = AppPreferences(allowedCountryCode: "NL",
                                        accessConfiguration: strictRules ? .migrating(country: "NL") : nil)
        defaults.set(try JSONEncoder().encode(preferences), forKey: "armor.preferences.v1")
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return defaults
    }

    private func observation(_ provider: EgressProvider, country: String = "NL") throws -> EgressObservation {
        let body: [String: Any] = provider == .ipWhoIS
            ? ["success": true, "ip": "203.0.113.7", "country_code": country]
            : ["ip": "203.0.113.7", "country": country]
        return try .decode(JSONSerialization.data(withJSONObject: body), provider: provider)
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<1_000 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("Verification did not settle")
    }

    func testRateLimitRecoversOnlyAfterThreeFreshRoundsAndDisplaysActualSources() async throws {
        var date = Date()
        var requests: [EgressProvider] = []
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try defaults(), startsMonitoring: false, now: { date },
                             diagnosticsReader: { .notChecked }, egressReader: { provider in
            requests.append(provider)
            if provider == .ipInfo { throw EgressError.httpStatus(429) }
            return try self.observation(provider)
        }, processProtection: controller, recoverySuccesses: 3)
        defer { model.shutdownProtection() }
        for index in 0..<3 {
            date += 2
            model.refreshExternalIP()
            await settle(model)
            XCTAssertEqual(model.protection.isOperational, index == 2)
        }
        XCTAssertEqual(requests.filter { $0 == .ipInfo }.count, 1)
        XCTAssertEqual(requests.filter { $0 == .ipWhoIS }.count, 3)
        XCTAssertEqual(requests.filter { $0 == .geoJS }.count, 3)
        XCTAssertEqual(model.countryComparison?.services, "ipwho.is + GeoJS")
        let detail = StatusPanelContent(model: model).externalDetail
        XCTAssertTrue(detail.contains("ipwho.is + GeoJS"))
        XCTAssertFalse(detail.contains("IPinfo"))
    }

    func testStrictRulesUseAuthoritativeCountryWhenBackupGeoIPDiffers() async throws {
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try defaults(strictRules: true), startsMonitoring: false,
                             diagnosticsReader: { .notChecked }, egressReader: { provider in
            if provider == .ipInfo { throw EgressError.httpStatus(429) }
            return try self.observation(provider, country: provider == .geoJS ? "RU" : "NL")
        }, processProtection: controller)
        defer { model.shutdownProtection() }
        model.refreshExternalIP()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        XCTAssertTrue(model.accessDecision(for: .desktop).allowed)
        XCTAssertTrue(model.accessDecision(for: .code).allowed)
        XCTAssertEqual(model.countryComparison?.independentCountry, "RU")
    }

    func testBothUnavailableKeepClaudePausedAndExposeSpecificCause() async throws {
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: try defaults(), startsMonitoring: false,
                             diagnosticsReader: { .notChecked }, egressReader: { provider in
            if provider == .ipInfo { throw EgressError.httpStatus(429) }
            if provider == .geoJS { throw EgressError.httpStatus(503) }
            return try self.observation(provider)
        }, processProtection: controller)
        defer { model.shutdownProtection() }
        model.refreshExternalIP()
        await settle(model)
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertNil(model.confirmedEgressObservation)
        guard case .failed(let message) = model.externalCheck else { return XCTFail("Missing diagnostic") }
        XCTAssertTrue(message.contains("GeoJS"))
        XCTAssertTrue(message.contains("503"))
    }

    func testLiveIndependentVerificationWithoutStartingProtection() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_LIVE_EGRESS_TEST"] == "1",
                         "Opt-in external service check")
        let result = try await EgressVerifier().check(primary: .ipWhoIS) { provider, address in
            try await EgressChecker(provider: provider).check(address: address)
        }
        XCTAssertEqual(result.observation.provider, .ipWhoIS)
        XCTAssertNotEqual(result.first.provider, result.second.provider)
        print("LIVE_EGRESS_VERIFIED: \(result.first.provider.title) + \(result.second.provider.title), country \(result.observation.countryCode)")
    }
}
