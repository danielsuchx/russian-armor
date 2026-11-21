import ArmorCore
import Foundation
import XCTest

final class AccessRulesTests: XCTestCase {
    func testCIDRMaskAndRepresentations() throws {
        let range = try XCTUnwrap(IPRange("203.0.113.25/24"))
        XCTAssertEqual(range.value, "203.0.113.0/24")
        XCTAssertTrue(range.contains("203.0.113.99"))
        XCTAssertFalse(range.contains("203.0.114.1"))
        XCTAssertTrue(range.contains("::ffff:203.0.113.99"))
        XCTAssertEqual(IPRange("::ffff:203.0.113.25/120")?.value, "203.0.113.0/24")
        XCTAssertEqual(IPRange("::ffff:203.0.113.25")?.value, "203.0.113.25")
        let v6 = try XCTUnwrap(IPRange("2001:db8:abcd:1::f/64"))
        XCTAssertTrue(v6.contains("2001:0db8:abcd:0001::123"))
        XCTAssertFalse(v6.contains("2001:db8:abcd:2::1"))
        XCTAssertFalse(v6.contains("203.0.113.1"))
        XCTAssertTrue(IPRange("0.0.0.0/0")!.contains("198.51.100.1"))
        XCTAssertTrue(IPRange("::/0")!.contains("2001:db8::1"))
    }

    func testInvalidRangesCannotBecomeWildcard() {
        for value in ["", "example.com", "1.2.3.4/33", "::/129", "1.2.3.4/-1", "1.2.3.4/", "::1%lo0", "1.2.3.4\0evil", "1.2.3.4/24/2", "::ffff:1.2.3.4/80"] {
            XCTAssertNil(IPRange(value), value)
        }
    }

    func testDenyWinsAndCountryAndIPMustBothMatch() {
        let rules = AccessRules(allowedCountries: ["NL", "SE", "RU"], deniedCountries: ["RU"],
                                allowedIPs: [IPRange("203.0.113.0/24")!], deniedIPs: [IPRange("203.0.113.7")!])
        XCTAssertFalse(rules.evaluate(ip: "203.0.113.8", countries: ["RU"]).allowed)
        XCTAssertFalse(rules.evaluate(ip: "::ffff:203.0.113.7", countries: ["NL"]).allowed)
        XCTAssertFalse(rules.evaluate(ip: "198.51.100.1", countries: ["NL"]).allowed)
        XCTAssertFalse(rules.evaluate(ip: "203.0.113.8", countries: ["DE"]).allowed)
        XCTAssertTrue(rules.evaluate(ip: "203.0.113.8", countries: ["NL", "SE"]).allowed)
        XCTAssertFalse(rules.evaluate(ip: "203.0.113.8", countries: ["NL", "DE"]).allowed)
    }

    func testIndependentCountryMismatchUsesAuthorityButHonorsExplicitSecondaryDeny() {
        let rules = AccessRules(allowedCountries: ["DE"], deniedCountries: [])
        XCTAssertTrue(rules.evaluateIndependent(ip: "203.0.113.8", authoritativeCountry: "DE",
                                                secondaryCountry: "SC").allowed)

        let denying = AccessRules(allowedCountries: ["DE", "SC"], deniedCountries: ["SC"])
        XCTAssertFalse(denying.evaluateIndependent(ip: "203.0.113.8", authoritativeCountry: "DE",
                                                   secondaryCountry: "SC").allowed)
    }

    func testUnknownEmptyInvalidAndConflictingRulesFailClosed() {
        XCTAssertFalse(AccessRules().evaluate(ip: "203.0.113.1", countries: ["NL"]).allowed)
        let rules = AccessRules(allowedCountries: ["NL"])
        XCTAssertFalse(rules.evaluate(ip: nil, countries: ["NL"]).allowed)
        XCTAssertFalse(rules.evaluate(ip: "203.0.113.1", countries: []).allowed)
        XCTAssertFalse(rules.evaluate(ip: "203.0.113.1", countries: ["nl"]).allowed)
        XCTAssertFalse(AccessRules(allowedCountries: ["NLD"]).evaluate(ip: "203.0.113.1", countries: ["NL"]).allowed)
        XCTAssertFalse(AccessRules(allowedCountries: ["NL"], deniedCountries: ["NL"]).evaluate(ip: "203.0.113.1", countries: ["NL"]).allowed)
    }

    func testPreferencesMigrationAndRoundTripDoNotExpandLegacyCountry() throws {
        let old = try JSONDecoder().decode(AppPreferences.self, from: Data(#"{"allowedCountryCode":"SE","startAtLogin":false}"#.utf8))
        XCTAssertNil(old.accessConfiguration)
        let configuration = AccessConfiguration.migrating(country: old.allowedCountryCode)
        for application in ProtectedApplication.allCases {
            let rules = try XCTUnwrap(configuration.activeProfile).rules(for: application)
            XCTAssertEqual(rules.allowedCountries, ["SE"])
            XCTAssertFalse(rules.evaluate(ip: "203.0.113.1", countries: ["NL"]).allowed)
        }
        let preferences = AppPreferences(allowedCountryCode: "SE", accessConfiguration: configuration)
        let data = try JSONEncoder().encode(preferences)
        XCTAssertEqual(try JSONDecoder().decode(AppPreferences.self, from: data), preferences)
        XCTAssertFalse(AccessConfiguration.migrating(country: nil).activeProfile!.sharedRules.evaluate(ip: "203.0.113.1", countries: ["NL"]).allowed)
    }

    func testMissingProfileOrDuplicateIDCannotOpenAccess() throws {
        var configuration = AccessConfiguration.migrating(country: "SE")
        configuration.activeProfileID = UUID()
        XCTAssertFalse(configuration.isValid)
        configuration.activeProfileID = configuration.profiles[0].id
        configuration.profiles.append(configuration.profiles[0])
        XCTAssertFalse(configuration.isValid)
        let data = try JSONEncoder().encode(AppPreferences(accessConfiguration: configuration))
        XCTAssertThrowsError(try JSONDecoder().decode(AppPreferences.self, from: data))
    }

    func testSeparateApplicationRulesDoNotInheritAnUnrelatedAllow() {
        let profile = AccessProfile(sharedRules: .init(allowedCountries: ["NL"]), separateApplications: true,
                                    desktopRules: .init(allowedCountries: ["SE"]), codeRules: .init(allowedCountries: ["DE"]))
        XCTAssertTrue(profile.rules(for: .desktop).evaluate(ip: "203.0.113.1", countries: ["SE"]).allowed)
        XCTAssertFalse(profile.rules(for: .code).evaluate(ip: "203.0.113.1", countries: ["SE"]).allowed)
    }

    func testRecoveryNeedsSpacedSuccessesAndResetsForChangedExit() {
        var gate = RecoveryGate()
        let now = Date(timeIntervalSince1970: 1000)
        gate.observe(ip: "203.0.113.1", countries: ["NL"], at: now)
        gate.observe(ip: "203.0.113.1", countries: ["NL"], at: now.addingTimeInterval(1))
        XCTAssertEqual(gate.successes, 1)
        gate.observe(ip: "203.0.113.1", countries: ["NL"], at: now.addingTimeInterval(2))
        XCTAssertFalse(gate.isReady)
        gate.observe(ip: "203.0.113.1", countries: ["NL"], at: now.addingTimeInterval(4))
        XCTAssertTrue(gate.isReady)
        gate.observe(ip: "203.0.113.2", countries: ["NL"], at: now.addingTimeInterval(6))
        XCTAssertEqual(gate.successes, 1)
        gate.observe(ip: "203.0.113.2", countries: ["SE"], at: now.addingTimeInterval(8))
        XCTAssertEqual(gate.successes, 1)
        gate.reset()
        XCTAssertEqual(gate.successes, 0)
    }
}
