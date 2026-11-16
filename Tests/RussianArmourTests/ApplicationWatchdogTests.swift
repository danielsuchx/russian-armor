import Foundation
import XCTest
@testable import RussianArmour

final class ApplicationWatchdogTests: XCTestCase {
    func testRequestRoundTripsWithoutLosingPathsOrProcessIdentity() throws {
        let expected = ProtectedProcessIdentity(pid: 42, startSeconds: 123, startMicroseconds: 456)
        let clean = URL(fileURLWithPath: "/tmp/Clean Exit Marker")
        let bundle = URL(fileURLWithPath: "/Applications/Russian Armour.app")
        let arguments = ["RussianArmour", WatchdogRequest.flag, "42", "123", "456", clean.path, bundle.path]
        let request = try XCTUnwrap(WatchdogRequest(arguments: arguments))
        XCTAssertEqual(request.parent, expected)
        XCTAssertEqual(request.cleanExitURL, clean)
        XCTAssertEqual(request.bundleURL, bundle)
        XCTAssertEqual(request.arguments, Array(arguments.dropFirst()))
    }

    func testRequestRejectsMalformedOrUnscopedInvocation() {
        XCTAssertNil(WatchdogRequest(arguments: ["RussianArmour"]))
        XCTAssertNil(WatchdogRequest(arguments: ["RussianArmour", WatchdogRequest.flag, "0", "1", "2", "/tmp/x", "/tmp/y"]))
        XCTAssertNil(WatchdogRequest(arguments: ["RussianArmour", "--other", "42", "1", "2", "/tmp/x", "/tmp/y"]))
    }
}
