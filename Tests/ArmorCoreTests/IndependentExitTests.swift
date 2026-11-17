import Foundation
import XCTest
@testable import ArmorCore

@MainActor
final class IndependentExitTests: XCTestCase {
    private func response(_ provider: EgressProvider, ip: String = "203.0.113.7") throws -> EgressObservation {
        let body: [String: Any] = provider == .ipWhoIS
            ? ["success": true, "ip": ip, "country_code": "NL"] : ["ip": ip, "country": "NL"]
        return try .decode(JSONSerialization.data(withJSONObject: body), provider: provider)
    }

    func testEachServiceMustObserveItsOwnRequestNotLookUpThePrimaryAddress() async throws {
        for primary in EgressProvider.allCases {
            var calls: [EgressProvider] = []
            let result = try await EgressVerifier().check(primary: primary, mode: .independentExit) { provider, address in
                XCTAssertNil(address, "A lookup of the first IP cannot confirm the second request's exit")
                calls.append(provider)
                return try self.response(provider)
            }
            XCTAssertEqual(calls, [primary, primary.alternate])
            XCTAssertEqual(result.observation.provider, .ipWhoIS)
        }
    }

    func testBackupAlsoObservesItsOwnExitAndHonorsCooldown() async throws {
        let date = Date(timeIntervalSince1970: 1000)
        let verifier = EgressVerifier(now: { date })
        var calls: [EgressProvider] = []
        for _ in 0..<2 {
            let result = try await verifier.check(primary: .ipWhoIS, mode: .independentExit) { provider, address in
                XCTAssertNil(address)
                calls.append(provider)
                if provider == .ipInfo { throw EgressError.rateLimited(until: date.addingTimeInterval(120)) }
                return try self.response(provider)
            }
            XCTAssertEqual(result.second.provider, .geoJS)
        }
        XCTAssertEqual(calls, [.ipWhoIS, .ipInfo, .geoJS, .ipWhoIS, .geoJS])
    }

    func testMismatchCannotBeVotedAwayByQueryingAnotherProvider() async throws {
        var calls: [EgressProvider] = []
        do {
            _ = try await EgressVerifier().check(primary: .ipWhoIS, mode: .independentExit) { provider, address in
                XCTAssertNil(address)
                calls.append(provider)
                return try self.response(provider, ip: provider == .ipWhoIS ? "203.0.113.7" : "203.0.113.8")
            }
            XCTFail("Different exits must revoke admission")
        } catch { XCTAssertEqual(error as? EgressError, .providersDisagree) }
        XCTAssertEqual(calls, [.ipWhoIS, .ipInfo])
    }

    func testExplicitLookupModeRemainsAvailableForSystemFirewallPolicy() async throws {
        var addresses: [String?] = []
        _ = try await EgressVerifier().check(primary: .ipWhoIS, mode: .addressLookup) { provider, address in
            addresses.append(address)
            return try self.response(provider)
        }
        XCTAssertEqual(addresses.count, 2)
        XCTAssertNil(addresses[0])
        XCTAssertEqual(addresses[1], "203.0.113.7")
    }
}
