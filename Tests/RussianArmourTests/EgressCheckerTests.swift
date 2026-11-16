import Foundation
import XCTest
import ArmourCore
@testable import RussianArmour

/// Every URL is intercepted in memory. No loopback or external server is used.
private final class EgressFixtureProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var requests: [String: [URL]] = [:]

    static func takeRequests(_ id: String) -> [URL] {
        lock.lock()
        defer { lock.unlock() }
        return requests.removeValue(forKey: id) ?? []
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let id = request.value(forHTTPHeaderField: "X-Fixture-ID"),
              let scenario = request.value(forHTTPHeaderField: "X-Fixture-Scenario"),
              let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        Self.lock.lock()
        Self.requests[id, default: []].append(url)
        Self.lock.unlock()
        if scenario == "tls" {
            client?.urlProtocol(self, didFailWithError: URLError(.secureConnectionFailed))
            return
        }
        let body: Data
        let status: Int
        switch scenario {
        case "rate-limit":
            status = 429
            body = Data()
        case "rejected":
            status = 200
            body = Data(#"{"success":false,"message":"fixture rejection"}"#.utf8)
        case "oversized":
            status = 200
            body = Data(repeating: 32, count: 4097)
        default:
            status = 200
            body = url.host == EgressProvider.ipInfo.host
                ? Data(#"{"ip":"2001:db8::7","country":"NL"}"#.utf8)
                : Data(#"{"success":true,"ip":"2001:db8::7","country_code":"NL"}"#.utf8)
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class EgressCheckerTests: XCTestCase {
    private func checker(provider: EgressProvider, scenario: String) -> (EgressChecker, String) {
        let id = UUID().uuidString
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [EgressFixtureProtocol.self]
        configuration.httpAdditionalHeaders = ["X-Fixture-ID": id, "X-Fixture-Scenario": scenario]
        return (EgressChecker(provider: provider, configuration: configuration), id)
    }

    func testEachProviderUsesOnlyItsOwnEndpointAndSchema() async throws {
        for provider in EgressProvider.allCases {
            let (checker, id) = checker(provider: provider, scenario: "success")
            let observation: EgressObservation
            do {
                observation = try await checker.check()
            } catch {
                _ = EgressFixtureProtocol.takeRequests(id)
                throw error
            }
            XCTAssertEqual(observation.ip, "2001:db8::7")
            XCTAssertEqual(observation.countryCode, "NL")
            XCTAssertEqual(observation.provider, provider)
            XCTAssertEqual(EgressFixtureProtocol.takeRequests(id), [provider.endpoint])
        }
    }

    func testTLSFailureDoesNotSendRequestToAlternativeProvider() async {
        let (checker, id) = checker(provider: .ipInfo, scenario: "tls")
        do {
            _ = try await checker.check()
            XCTFail("TLS failure was accepted")
        } catch {
            XCTAssertEqual((error as NSError).domain, NSURLErrorDomain)
            XCTAssertEqual((error as NSError).code, URLError.secureConnectionFailed.rawValue)
        }
        XCTAssertEqual(EgressFixtureProtocol.takeRequests(id), [EgressProvider.ipInfo.endpoint])
    }

    func testHTTPApplicationFailureAndUnknownLengthOversizeAreRejected() async {
        let scenarios: [(String, EgressError)] = [
            ("rate-limit", .httpStatus(429)),
            ("rejected", .providerRejected),
            ("oversized", .responseTooLarge)
        ]
        for (scenario, expected) in scenarios {
            let (checker, id) = checker(provider: .ipWhoIS, scenario: scenario)
            do {
                _ = try await checker.check()
                XCTFail("Invalid response was accepted: \(scenario)")
            } catch {
                XCTAssertEqual(error as? EgressError, expected)
            }
            XCTAssertEqual(EgressFixtureProtocol.takeRequests(id), [EgressProvider.ipWhoIS.endpoint])
        }
    }
}
