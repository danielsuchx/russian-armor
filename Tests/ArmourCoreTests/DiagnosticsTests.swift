import Foundation
import XCTest
@testable import ArmourCore

final class DiagnosticsTests: XCTestCase {
    func testOnlyUpUtunInterfacesAreObserved() {
        let result = TunnelObservation.inspect([
            LocalInterface(name: "en0", isUp: true),
            LocalInterface(name: "utun2", isUp: true),
            LocalInterface(name: "utun2", isUp: true),
            LocalInterface(name: "utun10", isUp: true),
            LocalInterface(name: "utun1", isUp: false),
            LocalInterface(name: "utun", isUp: true),
            LocalInterface(name: "utunVPN", isUp: true)
        ])
        XCTAssertEqual(result, .observed(["utun2", "utun10"]))
    }

    func testNoLocalTunnelIsNotAnErrorForRouterVPN() {
        XCTAssertEqual(TunnelObservation.inspect([]), .observed([]))
        XCTAssertNotEqual(TunnelObservation.inspect([]), .unavailable)
        XCTAssertEqual(VPNLocation.router.title, "На роутере")
    }

    func testOldPreferencesMigrateWithoutResettingToggles() throws {
        let old = Data(#"{"showInterfaceNames":false,"recordNetworkEvents":false}"#.utf8)
        let preferences = try JSONDecoder().decode(AppPreferences.self, from: old)
        XCTAssertFalse(preferences.showInterfaceNames)
        XCTAssertFalse(preferences.recordNetworkEvents)
        XCTAssertEqual(preferences.vpnLocation, .unspecified)
    }

    func testRouterPreferenceRoundTrip() throws {
        let preferences = AppPreferences(vpnLocation: .router)
        XCTAssertEqual(try JSONDecoder().decode(AppPreferences.self, from: JSONEncoder().encode(preferences)), preferences)
    }

    func testIPv4Response() throws {
        let date = Date(timeIntervalSince1970: 123)
        let result = try EgressObservation.decode(Data(#"{"ip":"203.0.113.9","country":"NL"}"#.utf8), checkedAt: date)
        XCTAssertEqual(result.ip, "203.0.113.9")
        XCTAssertEqual(result.countryCode, "NL")
        XCTAssertEqual(result.checkedAt, date)
    }

    func testIPv6Response() throws {
        let result = try EgressObservation.decode(Data(#"{"ip":"2001:db8::1","country":"DE"}"#.utf8))
        XCTAssertEqual(result.ip, "2001:db8::1")
    }

    func testInvalidIPsAreRejected() {
        for value in ["", "example.com", "999.1.1.1", "127.0.0.1/path", "fe80::1%en0", "1.2.3.4\u{0000}suffix", "1.2.3.4\n"] {
            let data = try! JSONSerialization.data(withJSONObject: ["ip": value, "country": "NL"])
            XCTAssertThrowsError(try EgressObservation.decode(data), "Accepted \(value)")
        }
    }

    func testInvalidAndMissingCountryAreRejected() {
        for value in ["", "nl", "NLD", "🇳🇱", "N\n"] {
            let data = try! JSONSerialization.data(withJSONObject: ["ip": "203.0.113.1", "country": value])
            XCTAssertThrowsError(try EgressObservation.decode(data))
        }
        XCTAssertThrowsError(try EgressObservation.decode(Data(#"{"ip":"203.0.113.1","country":null}"#.utf8)))
        XCTAssertThrowsError(try EgressObservation.decode(Data(#"{"ip":"203.0.113.1"}"#.utf8)))
    }

    func testMalformedAndOversizedResponseAreRejected() {
        XCTAssertThrowsError(try EgressObservation.decode(Data("not json".utf8)))
        XCTAssertThrowsError(try EgressObservation.decode(Data(repeating: 32, count: 4097))) { error in
            XCTAssertEqual(error as? EgressError, .responseTooLarge)
        }
    }
}
