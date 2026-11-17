import ArmorCore
import XCTest
@testable import ArmorFirewall

final class FirewallTests: XCTestCase {
    private var configuration: FirewallConfiguration {
        .init(physicalInterface: "en0", vpnOwnerKey: "TEAM/vpn.client",
              endpoints: [.init(address: "192.0.2.10", port: 51820, transport: "udp")],
              probeAddresses: ["ipwho.is": "192.0.2.20", "ipinfo.io": "192.0.2.30"],
              rules: .init(allowedCountries: ["NL"], deniedCountries: ["RU"]))
    }
    private var tunnel: FirewallTunnel {
        .init(interface: "utun4", addresses: ["10.0.0.2", "2001:db8::2"], identity: "owner|pid-start|utun4|addresses")
    }
    func testBlockedRulesHaveNoGeneralDNSLANOrPhysicalInternetException() throws {
        let text = try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false)
        XCTAssertTrue(text.hasSuffix("block drop quick all\n"))
        XCTAssertTrue(text.contains("on en0 inet proto udp from any to 192.0.2.10 port 51820 no state"))
        XCTAssertFalse(text.contains("port 53"))
        XCTAssertFalse(text.contains("utun"))
        XCTAssertFalse(text.contains("keep state"))
        XCTAssertTrue(text.split(separator: "\n").filter { $0.hasPrefix("pass") }.allSatisfy { $0.hasSuffix("no state") })
    }
    func testRecoveryAllowsOnlyRootProbesOnExactTunnelAndAddresses() throws {
        let text = try FirewallRules.render(configuration: configuration, tunnel: tunnel, allowTraffic: false)
        XCTAssertTrue(text.contains("on utun4 inet proto tcp from 10.0.0.2 to 192.0.2.20 port 443 user 0 flags any no state"))
        XCTAssertFalse(text.contains("on utun4 inet6"))
        XCTAssertFalse(text.contains("from 10.0.0.2 to any"))
    }
    func testAllowedTrafficStillCannotLeavePhysicalInterfaceExceptBootstrap() throws {
        let text = try FirewallRules.render(configuration: configuration, tunnel: tunnel, allowTraffic: true)
        XCTAssertTrue(text.contains("pass out quick on utun4 inet from 10.0.0.2 to any no state"))
        XCTAssertFalse(text.contains("pass out quick on utun4 inet6"))
        XCTAssertFalse(text.contains("pass out quick on en0 all"))
        XCTAssertThrowsError(try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: true))
    }
    func testRejectsInjectionCIDRHostnamesWildcardPortsAndWrongInterfaces() throws {
        for iface in ["en0\npass all", "utun0", "en", "en-1", "en0 "] {
            let value = FirewallConfiguration(physicalInterface: iface, vpnOwnerKey: configuration.vpnOwnerKey,
                endpoints: configuration.endpoints, probeAddresses: configuration.probeAddresses, rules: configuration.rules)
            XCTAssertFalse(value.isValid)
            XCTAssertThrowsError(try FirewallRules.render(configuration: value, tunnel: nil, allowTraffic: false))
        }
        for address in ["vpn.example.com", "0.0.0.0/0", "127.0.0.1", "192.0.2.1\npass all", "::1"] {
            XCTAssertFalse(VPNEndpoint(address: address, port: 443, transport: "tcp").isValid)
        }
        XCTAssertFalse(VPNEndpoint(address: "192.0.2.1", port: 0, transport: "udp").isValid)
        XCTAssertFalse(VPNEndpoint(address: "192.0.2.1", port: 443, transport: "any").isValid)
        XCTAssertThrowsError(try FirewallRules.render(configuration: configuration,
            tunnel: .init(interface: "utun4\npass all", addresses: ["10.0.0.2"], identity: "x"), allowTraffic: true))
    }
    func testRootPolicyRequiresExplicitCountriesAndBothProbeAddresses() {
        let value = FirewallConfiguration(physicalInterface: "en0", vpnOwnerKey: "TEAM/vpn.client",
            endpoints: configuration.endpoints, probeAddresses: [:], rules: .init())
        XCTAssertFalse(value.isValid)
        XCTAssertFalse(configuration.rules.evaluate(ip: "192.0.2.1", countries: ["NL", "RU"]).allowed)
    }
    func testAnchorIsBeforeAppleAndCustomConfigurationIsNeverReplaced() throws {
        let original = "# local comments\n" + FirewallRules.stockConfiguration
        let updated = try FirewallRules.installing(in: original)
        let statements = FirewallRules.statements(updated)
        XCTAssertLessThan(try XCTUnwrap(statements.firstIndex(of: FirewallRules.mainReference.trimmingCharacters(in: .newlines))),
                          try XCTUnwrap(statements.firstIndex(of: "anchor \"com.apple/*\"")))
        XCTAssertTrue(updated.contains("# local comments"))
        XCTAssertThrowsError(try FirewallRules.installing(in: original + "pass out quick all\n"))
        XCTAssertThrowsError(try FirewallRules.installing(in: updated))
        // A syntactically equivalent but mechanically unsupported representation
        // must not silently omit our anchor.
        XCTAssertThrowsError(try FirewallRules.installing(in: original.replacingOccurrences(of: "anchor \"com.apple/*\"\n", with: "  anchor \"com.apple/*\"  \n")))
    }
    func testRecoveryResetsForUnknownDeniedChangedTunnelAndExpiredEvidence() {
        var gate = FirewallRecovery()
        for time in [0.0, 2, 4] { gate.observe(tunnel: tunnel, ip: "192.0.2.4", countries: ["NL"], allowed: true, now: time) }
        XCTAssertTrue(gate.permits(tunnel, now: 5))
        XCTAssertFalse(gate.permits(tunnel, now: 34))
        let replacement = FirewallTunnel(interface: "utun4", addresses: tunnel.addresses, identity: "reused-interface-different-owner")
        XCTAssertFalse(gate.permits(replacement, now: 5))
        gate.observe(tunnel: replacement, ip: "192.0.2.4", countries: ["NL"], allowed: true, now: 6)
        XCTAssertEqual(gate.successes, 1)
        gate.observe(tunnel: replacement, ip: "192.0.2.4", countries: ["RU"], allowed: false, now: 8)
        XCTAssertEqual(gate.successes, 0)
        XCTAssertFalse(gate.permits(replacement, now: 8))
    }
    func testRecoveryDoesNotCountFastRepeatsAndResetsOnChangedIP() {
        var gate = FirewallRecovery()
        for time in [0.0, 0.1, 0.2] { gate.observe(tunnel: tunnel, ip: "192.0.2.4", countries: ["NL"], allowed: true, now: time) }
        XCTAssertEqual(gate.successes, 1)
        gate.observe(tunnel: tunnel, ip: "192.0.2.5", countries: ["NL"], allowed: true, now: 2)
        XCTAssertEqual(gate.successes, 1)
    }
    func testPFCommandsUseAnchorAndDoNotDisableGlobalPFOrFlushAllRules() throws {
        var calls: [[String]] = []
        let driver = PFDriver(command: { executable, arguments in
            XCTAssertEqual(executable, "/sbin/pfctl")
            calls.append(arguments)
            return arguments == ["-E"] ? "Token : 123456\n" : ""
        })
        try driver.applyAnchor(); try driver.flushStates(); XCTAssertEqual(try driver.acquireReference(), "123456"); try driver.releaseReference("123456")
        XCTAssertEqual(calls, [["-a", FirewallRules.anchor, "-f", FirewallPaths.anchor], ["-F", "states"], ["-E"], ["-X", "123456"]])
        XCTAssertFalse(calls.contains(["-d"]))
        XCTAssertFalse(calls.contains(["-F", "all"]))
    }
    func testUnexpectedLiveRulesRejectProtectionClaim() throws {
        let driver = PFDriver(command: { _, _ in "pass out quick all\nanchor \"app.russian-armor\" quick all\n" })
        XCTAssertThrowsError(try driver.verifyMain(armed: true))
    }
    func testActivationCannotReportSuccessIfAnyStepFails() throws {
        let expected: [[String]] = [["-n", "-f", FirewallPaths.main], ["-f", FirewallPaths.main],
                                   ["-E"], ["-F", "states"], ["-s", "rules"]]
        for failure in expected.indices {
            var calls: [[String]] = []
            let driver = PFDriver(command: { _, arguments in
                calls.append(arguments)
                if calls.count - 1 == failure { throw FirewallError.commandFailed("fixture") }
                if arguments == ["-s", "rules"] { return "anchor \"app.russian-armor\" quick all\nanchor \"com.apple/*\" all\n" }
                return arguments == ["-E"] ? "Token : 123456\n" : ""
            })
            XCTAssertThrowsError(try driver.activateMain(ensureEnabled: { _ = try driver.acquireReference() }))
            XCTAssertEqual(calls, Array(expected.prefix(failure + 1)))
            XCTAssertFalse(calls.contains(["-d"]))
        }
    }
    func testTranslationPassRulesCannotSilentlyBypassFilteringAnchor() throws {
        let driver = PFDriver(command: { _, _ in "nat-anchor \"com.apple/*\" all {\nnat pass on en0 from any to any -> (en0)\n}\n" })
        XCTAssertThrowsError(try driver.verifyNoTranslations())
    }
    func testSystemPFParserAcceptsGeneratedModesWithoutLoadingRules() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-pf-parse-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        for (index, parameters) in [(nil, false), (Optional(tunnel), false), (Optional(tunnel), true)].enumerated() {
            let rules = try FirewallRules.render(configuration: configuration, tunnel: parameters.0, allowTraffic: parameters.1)
            let path = directory.appendingPathComponent("rules-\(index).pf")
            try Data(rules.utf8).write(to: path)
            // -n is parse-only; no sudo, no /dev/pf mutation and no packet traffic.
            try PFDriver().validate(path.path)
        }
    }
    func testBoundedFileReaderRejectsSymlinksAndOversizedInputWithoutRoot() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-file-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("config")
        let link = directory.appendingPathComponent("link")
        try Data(repeating: 0, count: 100).write(to: target)
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: target.path)
        XCTAssertThrowsError(try RootFiles.read(link.path, rootOwned: false))
        XCTAssertThrowsError(try RootFiles.read(target.path, rootOwned: false, limit: 99))
        XCTAssertEqual(try RootFiles.read(target.path, rootOwned: false, limit: 100).count, 100)
    }
    func testStatusBecomesUnverifiedAfterMissingHeartbeatOrClockReversal() {
        let date = Date(timeIntervalSince1970: 100)
        let status = FirewallStatus(state: .protected, updatedAt: date, detail: "test")
        XCTAssertTrue(status.isFresh(at: date.addingTimeInterval(5)))
        XCTAssertFalse(status.isFresh(at: date.addingTimeInterval(7)))
        XCTAssertFalse(status.isFresh(at: date.addingTimeInterval(-1)))
    }
}
