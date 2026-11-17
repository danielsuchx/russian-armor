import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

final class ApplicationWatchdogTests: XCTestCase {
    func testRequestRoundTripsWithoutLosingPathsOrProcessIdentity() throws {
        let expected = ProtectedProcessIdentity(pid: 42, startSeconds: 123, startMicroseconds: 456)
        let clean = URL(fileURLWithPath: "/tmp/Clean Exit Marker")
        let bundle = URL(fileURLWithPath: "/Applications/Russian Armor.app")
        let arguments = ["RussianArmor", WatchdogRequest.flag, "42", "123", "456", clean.path, bundle.path]
        let request = try XCTUnwrap(WatchdogRequest(arguments: arguments))
        XCTAssertEqual(request.parent, expected)
        XCTAssertEqual(request.cleanExitURL, clean)
        XCTAssertEqual(request.bundleURL, bundle)
        XCTAssertEqual(request.arguments, Array(arguments.dropFirst()))
    }

    func testMalformedHelperFlagExitsWithoutStartingASecondApp() {
        XCTAssertTrue(ApplicationWatchdog.runHelperIfRequested(arguments: ["RussianArmor", WatchdogRequest.flag]))
        XCTAssertFalse(ApplicationWatchdog.runHelperIfRequested(arguments: ["RussianArmor"]))
    }

    func testRequestRejectsMalformedOrUnscopedInvocation() {
        XCTAssertNil(WatchdogRequest(arguments: ["RussianArmor"]))
        XCTAssertNil(WatchdogRequest(arguments: ["RussianArmor", WatchdogRequest.flag, "0", "1", "2", "/tmp/x", "/tmp/y"]))
        XCTAssertNil(WatchdogRequest(arguments: ["RussianArmor", "--other", "42", "1", "2", "/tmp/x", "/tmp/y"]))
    }
}
