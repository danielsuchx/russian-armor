import Darwin
import XCTest
@testable import RussianArmor

final class RouteChangeObserverTests: XCTestCase {
    func testRoutingSocketMessagesRecognizePotentialRouteChanges() {
        for type in [RTM_ADD, RTM_DELETE, RTM_CHANGE, RTM_REDIRECT] {
            XCTAssertTrue(RouteChangeObserver.containsRouteChange([4, 0, UInt8(RTM_VERSION), UInt8(type)][...]))
        }
        XCTAssertTrue(RouteChangeObserver.containsRouteChange([1][...]))
        XCTAssertFalse(RouteChangeObserver.containsRouteChange([4, 0, UInt8(RTM_VERSION), UInt8(RTM_GET)][...]))
    }

    func testFilterIgnoresInitialAndDuplicateFingerprintsButAcceptsRealChanges() {
        let wifi = RouteFingerprint(value: "en0|192.168.1.2|192.168.1.1")
        let vpn = RouteFingerprint(value: "utun4|10.0.0.2|10.0.0.1")
        var filter = RouteChangeFilter()
        XCTAssertFalse(filter.accepts(wifi))
        XCTAssertFalse(filter.accepts(wifi))
        XCTAssertTrue(filter.accepts(vpn))
        XCTAssertFalse(filter.accepts(vpn))
        XCTAssertTrue(filter.accepts(wifi))
    }
}
