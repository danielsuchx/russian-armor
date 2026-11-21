import ArmorCore
import Foundation
import Combine
import XCTest
@testable import RussianArmor

@MainActor
final class PacketGuardTests: XCTestCase {
    func testUnchangedPollingDoesNotPublishButMissingStatusStillRevokesProtection() throws {
        let suite = "PacketGuard.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        var status: FirewallStatus? = .init(state: .protected, detail: "ready", policy: "owned-vpn")
        let store = PacketGuardStore(defaults: defaults, monitoring: false, reader: { status })
        var notifications = 0
        let subscription = store.objectWillChange.sink { notifications += 1 }
        defer { subscription.cancel() }
        for _ in 0..<5 { store.refresh() }
        XCTAssertEqual(notifications, 0)
        XCTAssertTrue(store.permitsClaude)
        status = nil
        store.refresh()
        XCTAssertGreaterThan(notifications, 0)
        XCTAssertTrue(store.required)
        XCTAssertFalse(store.permitsClaude)
    }

    func testStrictModeNeverGrantsPermissionFromMissingOldOrWrongPolicyStatus() throws {
        let suite = "PacketGuard.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: "armor.packet-guard.required")
        for status: FirewallStatus? in [nil,
            .init(state: .protected, updatedAt: Date().addingTimeInterval(-10), detail: "stale", policy: "owned-vpn"),
            .init(state: .protected, detail: "old service"),
            .init(state: .protected, detail: "external", policy: "external-vpn"),
            .init(state: .recovering, detail: "checking", policy: "owned-vpn"),
            .init(state: .broken, detail: "error", policy: "owned-vpn")] {
            let store = PacketGuardStore(defaults: defaults, monitoring: false, reader: { status })
            XCTAssertTrue(store.required)
            XCTAssertFalse(store.permitsClaude)
        }
        let store = PacketGuardStore(defaults: defaults, monitoring: false, reader: { .init(state: .protected, detail: "ready", policy: "owned-vpn") })
        XCTAssertTrue(store.permitsClaude)
    }
    func testInstalledArmedStatusRemainsRequiredWithoutAPreferenceAndRevokesOnLoss() throws {
        let suite = "PacketGuard.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        var status: FirewallStatus? = .init(state: .protected, detail: "ready", policy: "owned-vpn")
        let store = PacketGuardStore(defaults: defaults, monitoring: false, reader: { status })
        XCTAssertTrue(store.required)
        XCTAssertTrue(store.permitsClaude)
        status = .init(state: .blocked, detail: "down", policy: "owned-vpn")
        store.refresh()
        XCTAssertFalse(store.permitsClaude)
        status = nil; store.refresh()
        XCTAssertTrue(store.required)
        XCTAssertFalse(store.permitsClaude)
    }
}
