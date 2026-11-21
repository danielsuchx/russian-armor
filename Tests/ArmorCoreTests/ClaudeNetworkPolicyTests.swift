import ArmorCore
import XCTest

final class ClaudeNetworkPolicyTests: XCTestCase {
    func testUDPIsDeniedEvenWhenBothApplicationsAreAllowed() {
        let policy = ClaudeNetworkPolicy(desktopAllowed: true, codeAllowed: true, processes: [], issuedAtUptime: 100)
        for application in ProtectedApplication.allCases {
            XCTAssertFalse(policy.permits(application, udp: true, receivedAt: 100, now: 101))
            XCTAssertTrue(policy.permits(application, udp: false, receivedAt: 100, now: 101))
        }
    }
    func testExpiredOrFutureLeaseNeverAllowsTCP() {
        let policy = ClaudeNetworkPolicy(desktopAllowed: true, codeAllowed: true, processes: [], issuedAtUptime: 100)
        for instant in [99.9, 104, 10000] {
            XCTAssertFalse(policy.permits(.desktop, udp: false, receivedAt: 100, now: instant))
        }
    }
    func testCodeAndDesktopPermissionsStaySeparateAfterTransportRoundTrip() throws {
        let policy = ClaudeNetworkPolicy(desktopAllowed: false, codeAllowed: true, processes: [
            .init(identity: .init(pid: 123, startSeconds: 456, startMicroseconds: 7), application: .code)
        ], issuedAtUptime: 10)
        let decoded = try JSONDecoder().decode(ClaudeNetworkPolicy.self, from: JSONEncoder().encode(policy))
        XCTAssertFalse(decoded.permits(.desktop, udp: false, receivedAt: 10, now: 11))
        XCTAssertTrue(decoded.permits(.code, udp: false, receivedAt: 10, now: 11))
        XCTAssertEqual(decoded.processes.first?.identity, policy.processes.first?.identity)
    }
    func testDelayedIPCMessageCannotRenewAnExpiredPermission() {
        let policy = ClaudeNetworkPolicy(desktopAllowed: true, codeAllowed: true, processes: [], issuedAtUptime: 10)
        XCTAssertFalse(policy.permits(.desktop, udp: false, receivedAt: 15, now: 15))
    }
}
