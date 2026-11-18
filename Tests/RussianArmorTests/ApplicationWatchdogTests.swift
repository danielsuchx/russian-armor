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

    func testUpdateRelaunchAndRecoveryPreserveOrdinaryQuitSemantics() throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        let bundle = URL(fileURLWithPath: "/Applications/Russian Armor.app")
        let request = try XCTUnwrap(WatchdogRequest(arguments: ["Armor", WatchdogRequest.flag, "42", "123", "0", marker.path, bundle.path]))
        var events: [String] = []
        func finish() {
            ApplicationWatchdog.finish(request, pause: { events.append("pause") }, relaunch: {
                XCTAssertEqual($0, bundle)
                events.append("open")
            })
        }
        try Data().write(to: marker)
        finish()
        XCTAssertTrue(events.isEmpty)
        try Data("relaunch".utf8).write(to: marker)
        finish()
        XCTAssertEqual(events, ["pause", "open"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        events.removeAll()
        finish()
        XCTAssertEqual(events, ["pause", "open"])
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
