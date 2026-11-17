@testable import ArmorTunnel
import ArmorCore
import Darwin
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class AccessIntegrationTests: XCTestCase {
    private func observation(_ country: String = "NL", provider: EgressProvider = .ipInfo) throws -> EgressObservation {
        let text = provider == .ipInfo
            ? #"{"ip":"203.0.113.7","country":"\#(country)"}"#
            : #"{"success":true,"ip":"203.0.113.7","country_code":"\#(country)"}"#
        return try .decode(Data(text.utf8), provider: provider)
    }

    private func settle(_ condition: () -> Bool) async {
        for _ in 0..<1000 { if condition() { return }; await Task.yield() }
        XCTFail("Condition did not settle")
    }

    func testIndividualApplicationRulesPauseNewChildrenAndPreserveIdentity() {
        let desktop = ProtectedProcessRecord(identity: .init(pid: 90001, startSeconds: 1, startMicroseconds: 0),
                                             parentPID: 1, executablePath: "/fixture/Claude", processName: "Claude",
                                             isClaudeDesktopRoot: true, isClaudeCodeInterpreter: false, application: .desktop)
        let code = ProtectedProcessRecord(identity: .init(pid: 90002, startSeconds: 1, startMicroseconds: 0),
                                          parentPID: 1, executablePath: "/fixture/claude", processName: "claude",
                                          isClaudeDesktopRoot: false, isClaudeCodeInterpreter: false)
        var records = [desktop, code]
        var stopped = Set<pid_t>()
        var signals: [(pid_t, Int32)] = []
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { records },
            identityReader: { pid in records.first { $0.identity.pid == pid }?.identity },
            signaler: { pid, signal in signals.append((pid, signal)); if signal == SIGSTOP { stopped.insert(pid) } else if signal == SIGCONT { stopped.remove(pid) }; return 0 },
            isStopped: { stopped.contains($0) })
        let allow = AccessRules(allowedCountries: ["NL"]).evaluate(ip: "203.0.113.7", countries: ["NL"])
        let deny = AccessRules(allowedCountries: ["SE"]).evaluate(ip: "203.0.113.7", countries: ["NL"])
        controller.apply([.desktop: allow, .code: deny], country: "NL")
        XCTAssertFalse(stopped.contains(desktop.identity.pid))
        XCTAssertTrue(stopped.contains(code.identity.pid))
        var child = code
        child = ProtectedProcessRecord(identity: .init(pid: 90003, startSeconds: 2, startMicroseconds: 0), parentPID: code.identity.pid,
                                        executablePath: "/bin/sh", processName: "sh", isClaudeDesktopRoot: false, isClaudeCodeInterpreter: false)
        records.append(child)
        controller.enforce()
        XCTAssertTrue(stopped.contains(child.identity.pid))
        controller.pause("Network changed")
        XCTAssertTrue(stopped.contains(desktop.identity.pid))
        XCTAssertFalse(signals.contains { $0.0 == code.identity.pid && $0.1 == SIGCONT })
    }

    func testCatalogPropagatesApplicationToChildrenButCodeRootRemainsCode() {
        func record(_ pid: Int32, _ parent: Int32, _ path: String, desktop: Bool = false) -> ProtectedProcessRecord {
            .init(identity: .init(pid: pid, startSeconds: 1, startMicroseconds: 0), parentPID: parent,
                  executablePath: path, processName: URL(fileURLWithPath: path).lastPathComponent,
                  isClaudeDesktopRoot: desktop, isClaudeCodeInterpreter: false)
        }
        let records = ProtectedProcessCatalog.protectedRecords(from: [record(10, 1, "/Claude", desktop: true), record(11, 10, "/helper"),
                                                                     record(12, 11, "/claude"), record(13, 12, "/bin/sh")])
        XCTAssertEqual(records.map(\.application), [.desktop, .desktop, .code, .code])
    }

    func testSavingRulesInvalidatesPermissionAndDoesNotPersistObservedEndpoints() async throws {
        let suite = "RulesIntegration.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(try JSONEncoder().encode(AppPreferences(allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { try self.observation(provider: $0) }, processProtection: controller)
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertTrue(model.protection.isOperational)
        var configuration = AccessConfiguration.migrating(country: "SE")
        try model.saveAccessConfiguration(configuration)
        XCTAssertFalse(model.protection.isOperational)
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertFalse(model.accessDecision(for: .desktop).allowed)
        configuration.profiles[0].sharedRules.allowedCountries = ["NL"]
        try model.saveAccessConfiguration(configuration)
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertTrue(model.protection.isOperational)
        let persisted = try XCTUnwrap(defaults.data(forKey: "armor.preferences.v1"))
        XCTAssertFalse(String(decoding: persisted, as: UTF8.self).contains("203.0.113.7"))
        XCTAssertEqual(try JSONDecoder().decode(AppPreferences.self, from: persisted).accessConfiguration, configuration)
    }

    func testInvalidDraftDoesNotGetSilentlyPartiallySaved() throws {
        var draft = AccessRulesDraft(.init(allowedCountries: ["NL"]))
        draft.ips = "203.0.113.0/24\ninvalid"
        XCTAssertThrowsError(try draft.parsed())
        draft.ips = "::ffff:203.0.113.1"
        draft.countries = "nl, se"
        XCTAssertEqual(try draft.parsed().allowedCountries, ["NL", "SE"])
        XCTAssertEqual(try draft.parsed().allowedIPs.first?.value, "203.0.113.1")
        draft.deniedCountries = "Russia"
        XCTAssertThrowsError(try draft.parsed())
    }

    func testRecoveryRequiresThreeSpacedBoundChecksAndNeverFallsBackWhenTunnelFails() async throws {
        let suite = "BoundRecovery.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(try JSONEncoder().encode(AppPreferences(vpnLocation: .thisMac, allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
        var instant = Date()
        var fail = false
        var unrestrictedCalls = 0
        var boundCalls = 0
        let tunnel = VerifiedTunnel(interface: "utun4", owner: .init(pid: 99999, startSeconds: 1, startMicroseconds: 0),
                                    teamID: "TEAM", signingID: "vpn", sourceAddresses: ["10.8.0.2"])
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, now: { instant }, diagnosticsReader: { .notChecked },
                             egressReader: { provider in unrestrictedCalls += 1; return try self.observation(provider: provider) },
                             processProtection: controller, recoverySuccesses: 3,
                             tunnelEgressReader: { _ in
            boundCalls += 1
            if fail { throw TunnelCheckError.unavailable }
            return try TunnelCheckResult(first: self.observation(provider: .ipWhoIS), second: self.observation(), tunnel: tunnel)
        })
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        model.refreshExternalIP() // Same instant cannot count twice.
        await settle { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        for index in 1...2 {
            instant += 2
            model.refreshExternalIP()
            await settle { !model.externalCheck.isChecking }
            XCTAssertEqual(model.protection.isOperational, index == 2)
        }
        XCTAssertEqual(model.verifiedTunnel, tunnel)
        fail = true
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertNil(model.verifiedTunnel)
        XCTAssertEqual(unrestrictedCalls, 0)
        XCTAssertEqual(boundCalls, 5)
        fail = false
        instant += 2
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational, "Recovery must start over after failure")
    }

    func testRuleDisagreementDoesNotPermitOneDatabaseToOverrideDeny() async throws {
        let suite = "CountryDisagreement.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        var configuration = AccessConfiguration.migrating(country: "NL")
        configuration.profiles[0].sharedRules.deniedCountries = ["RU"]
        defaults.set(try JSONEncoder().encode(AppPreferences(accessConfiguration: configuration)), forKey: "armor.preferences.v1")
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { provider in try self.observation(provider == .ipWhoIS ? "NL" : "RU", provider: provider) },
                             processProtection: controller)
        model.refreshExternalIP()
        await settle { !model.externalCheck.isChecking }
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertEqual(model.accessDecision(for: .desktop).explanation, "Страна входит в список запретов.")
    }

    func testRealDisposableProcessSelfTest() async throws {
        try await ProtectionSelfTest.run()
    }
}
