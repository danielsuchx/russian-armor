import ArmorCore
import XCTest
@testable import RussianArmor

final class ProtectionIndicatorTests: XCTestCase {
    func testLegendExplainsEveryColor() {
        for color in ["Зелёный", "жёлтый", "красный", "серый"] {
            XCTAssertTrue(ProtectionIndicator.legend.localizedCaseInsensitiveContains(color))
        }
    }

    func testStrictFirewallTakesPriorityOverProcessState() {
        let now = Date()
        let protected = FirewallStatus(state: .protected, updatedAt: now, detail: "ready", policy: "owned-vpn")
        let blocked = FirewallStatus(state: .blocked, updatedAt: now, detail: "blocked", policy: "owned-vpn")
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .failed("process"), packetGuardRequired: true,
                                                   firewallStatus: protected, now: now).state, .green)
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .countryConfirmed, packetGuardRequired: true,
                                                   firewallStatus: blocked, now: now).state, .yellow)
    }

    func testMissingOrStaleStrictStatusIsRed() {
        let now = Date()
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .countryConfirmed, packetGuardRequired: true,
                                                   firewallStatus: nil, now: now).state, .red)
        let stale = FirewallStatus(state: .protected, updatedAt: now.addingTimeInterval(-7), detail: "old", policy: "owned-vpn")
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .countryConfirmed, packetGuardRequired: true,
                                                   firewallStatus: stale, now: now).state, .red)
    }

    func testProcessProtectionAndSleepStates() {
        let now = Date()
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .countryConfirmed, packetGuardRequired: false,
                                                   firewallStatus: nil, now: now).state, .green)
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .configuring("checking"), packetGuardRequired: false,
                                                   firewallStatus: nil, now: now).state, .yellow)
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .failed("failed"), packetGuardRequired: false,
                                                   firewallStatus: nil, now: now).state, .red)
        XCTAssertEqual(ProtectionIndicator.resolve(protection: .countryConfirmed, packetGuardRequired: false,
                                                   firewallStatus: nil, now: now, sleeping: true).state, .gray)
    }
}
