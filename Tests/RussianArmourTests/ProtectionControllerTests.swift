import Foundation
import NetworkExtension
import XCTest
@testable import RussianArmour

@MainActor
final class ProtectionControllerTests: XCTestCase {
    private let pin = String(repeating: "a", count: 64)

    private func endpoint(host: String = "192.168.50.1", port: UInt16 = 1080, username: String = "armour",
                          pin: String? = nil, version: Int = 1) -> ProtectionController.EndpointDescriptor {
        .init(version: version, host: host, port: port, username: username, routerCertificateSHA256: pin ?? self.pin)
    }

    func testLaunchAutomaticallyInstallsSavedConfigurationOnlyOnce() {
        var policy = ProtectionController.RecoveryPolicy()
        let now = Date()
        XCTAssertEqual(policy.action(hasPending: true, hasManager: false, rulesValid: false,
                                     enabled: false, sessionStatus: .invalid, now: now), .install)
        // A failed/denied request must not cause a new approval dialog every five seconds.
        XCTAssertEqual(policy.action(hasPending: true, hasManager: false, rulesValid: false,
                                     enabled: false, sessionStatus: .invalid, now: now.addingTimeInterval(60)), .wait)
    }

    func testInstalledChannelStartsOnLaunchAndRecoversAfterDisconnectWithBackoff() {
        var policy = ProtectionController.RecoveryPolicy()
        let now = Date()
        func action(_ status: NEVPNStatus, after seconds: TimeInterval) -> ProtectionController.RecoveryPolicy.Action {
            policy.action(hasPending: false, hasManager: true, rulesValid: true,
                          enabled: true, sessionStatus: status, now: now.addingTimeInterval(seconds))
        }
        XCTAssertEqual(action(.disconnected, after: 0), .start)
        XCTAssertEqual(action(.connecting, after: 1), .wait)
        XCTAssertEqual(action(.disconnected, after: 5), .wait)
        XCTAssertEqual(action(.invalid, after: 29), .wait)
        XCTAssertEqual(action(.disconnected, after: 30), .start)
        XCTAssertEqual(action(.connected, after: 31), .verify)
        // A new disconnect after a successful connection recovers immediately.
        XCTAssertEqual(action(.disconnected, after: 32), .start)
    }

    func testRecoveryNeverRestartsInFlightConnectionOrRecreatesRemovedConfiguration() {
        for status: NEVPNStatus in [.connecting, .reasserting, .disconnecting] {
            var policy = ProtectionController.RecoveryPolicy()
            XCTAssertEqual(policy.action(hasPending: false, hasManager: true, rulesValid: true,
                                         enabled: true, sessionStatus: status, now: Date()), .wait)
        }
        var policy = ProtectionController.RecoveryPolicy()
        XCTAssertEqual(policy.action(hasPending: false, hasManager: false, rulesValid: false,
                                     enabled: false, sessionStatus: .invalid, now: Date()), .configure)
    }

    func testLaunchRepairsDisabledOrIncompleteConfigurationBeforeStarting() {
        for (valid, enabled) in [(true, false), (false, true)] {
            var policy = ProtectionController.RecoveryPolicy()
            XCTAssertEqual(policy.action(hasPending: false, hasManager: true, rulesValid: valid,
                                         enabled: enabled, sessionStatus: .disconnected, now: Date()), .install)
        }
    }

    func testAppProxyConstructorIsPerApplicationWithoutUsingMisTypedInheritedFactory() {
        let manager = NEAppProxyProviderManager()
        XCTAssertEqual(manager.routingMethod, .sourceApplication)
        XCTAssertTrue(type(of: manager) == NEAppProxyProviderManager.self)
        // The inherited forPerAppVPN factory currently returns a NETunnelProviderManager
        // runtime object, not the NEAppProxyProviderManager subclass required by this app.
    }

    func testRouterEndpointRejectsPublicLoopbackDNSAndMalformedAddresses() throws {
        for host in ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.50.1"] {
            XCTAssertNoThrow(try ProtectionController.validate(endpoint(host: host)), host)
        }
        for host in ["127.0.0.1", "0.0.0.0", "203.0.113.4", "172.15.0.1", "172.32.0.1", "router.local", "::1",
                     "192.168.050.1", "192.168.1", "192.168.1.256", "192.168.1.1:1080", "https://192.168.1.1",
                     "192.168.1.1\n", "192.168.1.1/path", "192.168.1.1\u{0}"] {
            XCTAssertThrowsError(try ProtectionController.validate(endpoint(host: host)), host)
        }
        XCTAssertThrowsError(try ProtectionController.validate(endpoint(port: 0)))
        XCTAssertThrowsError(try ProtectionController.validate(endpoint(version: 2)))
    }

    func testPinnedAuthenticatedEndpointCannotDowngradeToUnpinnedOrAnonymousProxy() {
        for invalidPin in ["", String(repeating: "a", count: 63), String(repeating: "a", count: 65),
                           String(repeating: "g", count: 64), String(repeating: "A", count: 64)] {
            XCTAssertThrowsError(try ProtectionController.validate(endpoint(pin: invalidPin)))
        }
        XCTAssertThrowsError(try ProtectionController.validate(endpoint(username: "")))
        XCTAssertThrowsError(try ProtectionController.validate(endpoint(username: "armour\u{0}")))
        XCTAssertThrowsError(try ProtectionController.validate(endpoint(username: String(repeating: "я", count: 128))))
    }

    func testHeartbeatRequiresPinnedTransportAndCurrentConfiguration() throws {
        let identifier = UUID().uuidString
        let values: [String: Any] = ["version": 1, "ready": true, "configurationID": identifier, "transport": "tls-pinned-socks5"]
        func data(_ overrides: [String: Any] = [:]) throws -> Data {
            try JSONSerialization.data(withJSONObject: values.merging(overrides) { _, new in new })
        }
        XCTAssertTrue(ProtectionController.acceptsHeartbeat(try data(), configurationID: identifier))
        for changes: [String: Any] in [["ready": false], ["configurationID": UUID().uuidString], ["transport": "socks5"], ["version": 2]] {
            XCTAssertFalse(ProtectionController.acceptsHeartbeat(try data(changes), configurationID: identifier))
        }
        XCTAssertFalse(ProtectionController.acceptsHeartbeat(Data("{}".utf8), configurationID: identifier))
        XCTAssertFalse(ProtectionController.acceptsHeartbeat(Data(repeating: 32, count: 4097), configurationID: identifier))
        XCTAssertFalse(ProtectionController.acceptsHeartbeat(try data(), configurationID: "not-a-config-id"))
    }

    func testBuildWithoutExtensionCannotWriteCredentialsOrStartInstallation() async throws {
        let name = "ProtectionControllerTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let controller = ProtectionController(bundle: Bundle(for: Self.self), defaults: defaults, automaticallyRefresh: false)
        await controller.refresh()
        guard case .unavailable = controller.status else { return XCTFail("Automatic startup must expose the missing extension") }
        XCTAssertNil(defaults.persistentDomain(forName: name))
        let password = "fixture-only-secret"
        do {
            try await controller.configure(host: "192.168.50.1", port: 1080, username: "armour", password: password,
                                           routerCertificateSHA256: pin)
            XCTFail("An unprepared bundle must fail before any credential is written")
        } catch ProtectionController.ControllerError.unsupportedBuild { }
        guard case .unavailable = controller.status else { return XCTFail("The build limitation must be visible") }
        XCTAssertNil(defaults.persistentDomain(forName: name))
        do {
            try await controller.installAndEnable()
            XCTFail("An unprepared bundle must not submit an activation request")
        } catch ProtectionController.ControllerError.unsupportedBuild { }
        guard case .unavailable = controller.status else { return XCTFail("Installation must not look successful") }
        XCTAssertNil(defaults.persistentDomain(forName: name))
        do {
            try await controller.removeProtection()
            XCTFail("An unprepared bundle must not remove configurations or submit deactivation")
        } catch ProtectionController.ControllerError.unsupportedBuild { }
        guard case .unavailable = controller.status else { return XCTFail("Removal must reject the unprepared bundle") }
        XCTAssertNil(defaults.persistentDomain(forName: name))
    }
}
