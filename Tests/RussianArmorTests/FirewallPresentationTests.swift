import ArmorCore
import XCTest
@testable import RussianArmor

final class FirewallPresentationTests: XCTestCase {
    func testMissingStaleOrBrokenStatusDoesNotClaimNetworkProtection() {
        let now = Date(timeIntervalSince1970: 100)
        XCTAssertFalse(FirewallStatusPresentation(status: nil, now: now).verified)
        XCTAssertFalse(FirewallStatusPresentation(status: .init(state: .protected, updatedAt: now.addingTimeInterval(-7), detail: "old"), now: now).verified)
        XCTAssertFalse(FirewallStatusPresentation(status: .init(state: .broken, updatedAt: now, detail: "error"), now: now).verified)
        XCTAssertFalse(FirewallStatusPresentation(status: .init(state: .disabled, updatedAt: now, detail: "off"), now: now).verified)
    }
    func testFreshBlockedAndProtectedStatusesRemainDistinctFromProcessPause() {
        let now = Date()
        let blocked = FirewallStatusPresentation(status: .init(state: .blocked, updatedAt: now, detail: "blocked"), now: now)
        let allowed = FirewallStatusPresentation(status: .init(state: .protected, updatedAt: now, detail: "tunnel"), now: now)
        XCTAssertTrue(blocked.verified)
        XCTAssertTrue(allowed.verified)
        XCTAssertNotEqual(blocked.title, allowed.title)
        XCTAssertTrue(allowed.title.contains("Весь Mac"))
    }
}
