import Foundation
import XCTest
@testable import ArmourCore

final class EgressProviderTests: XCTestCase {
    func testProviderEndpointsAreExplicitHTTPSDestinations() {
        XCTAssertEqual(EgressProvider.countryIS.endpoint.absoluteString, "https://api.country.is/")
        XCTAssertEqual(EgressProvider.ipWhoIS.endpoint.absoluteString, "https://ipwho.is/?fields=success,ip,country_code")
        for provider in EgressProvider.allCases {
            XCTAssertEqual(provider.endpoint.scheme, "https")
            XCTAssertEqual(provider.endpoint.host, provider.host)
            XCTAssertNil(provider.endpoint.user)
            XCTAssertNil(provider.endpoint.password)
        }
    }

    func testIPWhoISIPv4AndIPv6Responses() throws {
        for ip in ["203.0.113.7", "2001:db8::7"] {
            let body = try JSONSerialization.data(withJSONObject: ["success": true, "ip": ip, "country_code": "NL"])
            let date = Date(timeIntervalSince1970: 123)
            let observation = try EgressObservation.decode(body, provider: .ipWhoIS, checkedAt: date)
            XCTAssertEqual(observation.ip, ip)
            XCTAssertEqual(observation.countryCode, "NL")
            XCTAssertEqual(observation.provider, .ipWhoIS)
            XCTAssertEqual(observation.checkedAt, date)
        }
    }

    func testCountryISRetainsItsOwnParserAndAttribution() throws {
        let observation = try EgressObservation.decode(Data(#"{"ip":"203.0.113.7","country":"NL"}"#.utf8))
        XCTAssertEqual(observation.provider, .countryIS)
    }

    func testProviderFailureWithHTTP200IsNotAccepted() {
        for body in [
            #"{"success":false,"message":"failure"}"#,
            #"{"success":false,"ip":"203.0.113.7","country_code":"NL"}"#
        ] {
            XCTAssertThrowsError(try EgressObservation.decode(Data(body.utf8), provider: .ipWhoIS)) {
                XCTAssertEqual($0 as? EgressError, .providerRejected)
            }
        }
    }

    func testProviderSchemasCannotBeConfused() {
        let country = Data(#"{"ip":"203.0.113.7","country":"NL"}"#.utf8)
        let whois = Data(#"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#.utf8)
        XCTAssertThrowsError(try EgressObservation.decode(country, provider: .ipWhoIS))
        XCTAssertThrowsError(try EgressObservation.decode(whois, provider: .countryIS))
    }

    func testAlternativeProviderRetainsValidationAndSizeBounds() {
        let invalid = [
            #"{"success":true,"ip":"example.com","country_code":"NL"}"#,
            #"{"success":true,"ip":"203.0.113.7","country_code":"nl"}"#,
            #"{"success":true,"ip":"203.0.113.7","country_code":null}"#,
            #"{"success":true,"country_code":"NL"}"#,
            #"{"ip":"203.0.113.7","country_code":"NL"}"#,
            #"{"success":"true","ip":"203.0.113.7","country_code":"NL"}"#
        ]
        for body in invalid {
            XCTAssertThrowsError(try EgressObservation.decode(Data(body.utf8), provider: .ipWhoIS))
        }
        XCTAssertThrowsError(try EgressObservation.decode(Data(repeating: 32, count: 4097), provider: .ipWhoIS)) {
            XCTAssertEqual($0 as? EgressError, .responseTooLarge)
        }
    }

    func testSafeNetworkReasonsDoNotExposeNSErrorPayload() {
        let codes: [URLError.Code] = [
            .secureConnectionFailed, .serverCertificateUntrusted, .timedOut,
            .cannotFindHost, .notConnectedToInternet, .networkConnectionLost, .unknown
        ]
        let privateText = "203.0.113.77 private-proxy-token https://private.example/secret"
        for code in codes {
            let error = NSError(domain: NSURLErrorDomain, code: code.rawValue, userInfo: [
                NSLocalizedDescriptionKey: privateText,
                NSURLErrorFailingURLErrorKey: URL(string: "https://private.example/secret")!
            ])
            let message = EgressError.safeMessage(for: error)
            XCTAssertTrue(message.contains(String(code.rawValue)) || message.contains("−\(abs(code.rawValue))"))
            XCTAssertFalse(message.contains("203.0.113.77"))
            XCTAssertFalse(message.contains("private"))
            XCTAssertFalse(message.contains("https://"))
        }
        let foreign = NSError(domain: "UntrustedProvider", code: -1200, userInfo: [NSLocalizedDescriptionKey: privateText])
        XCTAssertFalse(EgressError.safeMessage(for: foreign).contains("TLS"))
        XCTAssertFalse(EgressError.safeMessage(for: foreign).contains(privateText))
    }

    func testTLSHTTPAndDNSHaveDifferentActionableErrors() {
        let tls = EgressError.safeMessage(for: URLError(.secureConnectionFailed))
        let dns = EgressError.safeMessage(for: URLError(.cannotFindHost))
        let http = EgressError.safeMessage(for: EgressError.httpStatus(429))
        XCTAssertTrue(tls.contains("TLS"))
        XCTAssertTrue(tls.contains("−1200"))
        XCTAssertTrue(dns.contains("DNS"))
        XCTAssertTrue(http.contains("429"))
        XCTAssertNotEqual(tls, dns)
        XCTAssertNotEqual(tls, http)
    }
}
