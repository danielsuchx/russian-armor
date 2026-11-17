import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

/// In-memory URL loading; never reaches the host network or a local server.
private final class ServiceProbeFixture: URLProtocol {
    private static let lock = NSLock()
    private static var received: [String: [URLRequest]] = [:]
    static func take(_ id: String) -> [URLRequest] {
        lock.lock(); defer { lock.unlock() }
        return received.removeValue(forKey: id) ?? []
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let id = request.value(forHTTPHeaderField: "X-Fixture-ID")!
        let scenario = request.value(forHTTPHeaderField: "X-Fixture-Scenario")!
        Self.lock.lock(); Self.received[id, default: []].append(request); Self.lock.unlock()
        if scenario == "tls" {
            client?.urlProtocol(self, didFailWithError: URLError(.serverCertificateUntrusted)); return
        }
        let code = scenario == "limited" ? 429 : (scenario == "redirect" ? 302 : 200)
        let body = scenario == "oversized" ? Data(repeating: 65, count: 4097)
            : Data((scenario == "challenge" ? "<html>challenge</html>" : "ip=203.0.113.7\nloc=RU\n").utf8)
        let response = HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: "HTTP/1.1",
                                       headerFields: ["Retry-After": "900", "Location": "https://other.example/"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class ServiceProbeReaderTests: XCTestCase {
    private func configuration(_ scenario: String) -> (URLSessionConfiguration, String) {
        let id = UUID().uuidString
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ServiceProbeFixture.self]
        config.httpAdditionalHeaders = ["X-Fixture-ID": id, "X-Fixture-Scenario": scenario]
        return (config, id)
    }

    func testOnlyFixedServiceEndpointsAreQueriedWithoutCredentialsOrPersistentStorage() async throws {
        for service in ServiceProbe.allCases {
            let (config, id) = configuration("success")
            defer { _ = ServiceProbeFixture.take(id) }
            let address = try await ServiceProbeReader.read(service, configuration: config)
            XCTAssertEqual(address, "203.0.113.7")
            let requests = ServiceProbeFixture.take(id)
            XCTAssertEqual(requests.count, 1)
            XCTAssertEqual(requests.first?.url, service.url)
            XCTAssertEqual(requests.first?.httpMethod, "GET")
            XCTAssertNil(requests.first?.httpBody)
            XCTAssertNil(requests.first?.value(forHTTPHeaderField: "Authorization"))
            XCTAssertNil(requests.first?.value(forHTTPHeaderField: "Cookie"))
            XCTAssertNil(config.urlCredentialStorage)
            XCTAssertNil(config.httpCookieStorage)
            XCTAssertNil(config.urlCache)
            XCTAssertFalse(config.httpShouldSetCookies)
        }
    }

    func testTLSRedirectChallengeAndOversizedResponseAreNeverAccepted() async {
        for scenario in ["tls", "redirect", "challenge", "oversized"] {
            let (config, id) = configuration(scenario)
            do {
                _ = try await ServiceProbeReader.read(.desktop, configuration: config)
                XCTFail("Accepted \(scenario)")
            } catch { }
            XCTAssertEqual(ServiceProbeFixture.take(id).map(\.url), [ServiceProbe.desktop.url])
        }
    }

    func testServerRetryAfterReachesMonitorWithoutResponseContents() async {
        let (config, id) = configuration("limited")
        let start = Date()
        do {
            _ = try await ServiceProbeReader.read(.code, configuration: config)
            XCTFail("Accepted HTTP 429")
        } catch let failure as ServiceProbeFailure {
            XCTAssertEqual(failure.retryAt?.timeIntervalSince(start) ?? 0, 900, accuracy: 1)
        } catch { XCTFail("Lost attributed retry: \(error)") }
        XCTAssertEqual(ServiceProbeFixture.take(id).count, 1)
    }
}
