import ArmorCore
import Foundation
import XCTest
@testable import ArmorFirewall

final class OwnedVPNTests: XCTestCase {
    private var own: OwnedVPNConfiguration {
        .init(privateKey: Data(repeating: 1, count: 32).base64EncodedString(), peerPublicKey: Data(repeating: 2, count: 32).base64EncodedString(),
              clientAddress: "10.78.91.2", expectedExitIP: "192.0.2.10", physicalGateway: "192.168.1.1", networkService: "Wi-Fi",
              dnsServers: ["1.1.1.1"], coreSHA256: String(repeating: "a", count: 64))
    }
    private var configuration: FirewallConfiguration {
        .init(physicalInterface: "en0", vpnOwnerKey: "owned/wireguard", endpoints: [.init(address: "192.0.2.10", port: 51821, transport: "udp")],
              probeAddresses: ["ipwho.is": "192.0.2.20", "ipinfo.io": "192.0.2.30"], rules: .init(allowedCountries: ["DE"]), ownedVPN: own)
    }
    func testPhysicalBootstrapCannotBeUsedByOrdinaryClaudeProcesses() throws {
        let text = try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false)
        let physicalOutbound = text.split(separator: "\n").filter { $0.hasPrefix("pass out quick on en0") }
        XCTAssertEqual(physicalOutbound.count, 2)
        XCTAssertTrue(physicalOutbound.allSatisfy { $0.contains("user 0") && $0.hasSuffix("no state") })
        XCTAssertTrue(text.hasSuffix("block drop quick all\n"))
        XCTAssertFalse(text.contains("port 53"))
        XCTAssertFalse(text.contains("port 443"))
        XCTAssertFalse(text.contains("inet6"))
    }
    func testEstablishedTunnelStillDoesNotPermitDirectTCPUDPOrIPv6() throws {
        let tunnel = FirewallTunnel(interface: "utun9", addresses: ["10.78.91.2"], identity: "owned")
        let text = try FirewallRules.render(configuration: configuration, tunnel: tunnel, allowTraffic: true)
        XCTAssertTrue(text.contains("pass out quick on utun9 inet from 10.78.91.2 to any no state"))
        XCTAssertTrue(text.hasSuffix("block drop quick all\n"))
        XCTAssertFalse(text.contains("keep state"))
        XCTAssertFalse(text.contains("on en1"))
        XCTAssertFalse(text.contains("inet6"))
        XCTAssertFalse(text.contains("pass out quick on en0 inet proto tcp"))
        XCTAssertThrowsError(try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: true))
    }
    func testPrivateKeyUsesUAPIAndNeverAppearsAsBase64InGeneratedRules() throws {
        XCTAssertTrue(own.isValid)
        let request = try own.request(endpoint: configuration.endpoints[0])
        XCTAssertTrue(request.hasSuffix("\n\n"))
        XCTAssertTrue(request.contains("allowed_ip=0.0.0.0/0\n"))
        XCTAssertTrue(request.contains("endpoint=192.0.2.10:51821\n"))
        XCTAssertFalse(request.contains(own.privateKey))
        let pf = try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false)
        XCTAssertFalse(pf.contains(own.privateKey))
        let status = FirewallStatus(state: .recovering, detail: "Checking", policy: "owned-vpn")
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(status), as: UTF8.self).contains(own.privateKey))
    }
    func testAuthenticatedPeerCannotReuseOldChildOrExpiredHandshake() {
        var health = OwnedVPNHealth()
        XCTAssertFalse(health.permits(identity: "a", handshake: 100, now: 101))
        health.confirm(identity: "a")
        XCTAssertTrue(health.permits(identity: "a", handshake: 100, now: 101))
        XCTAssertFalse(health.permits(identity: "b", handshake: 100, now: 101))
        XCTAssertFalse(health.permits(identity: "a", handshake: 100, now: 281))
        XCTAssertFalse(health.permits(identity: "a", handshake: 100, now: 99))
        XCTAssertFalse(health.permits(identity: "a", handshake: 0, now: 1))
        health.reset()
        XCTAssertFalse(health.permits(identity: "a", handshake: 100, now: 101))
    }
    func testLegacyConfigurationAndStatusDecodeWithoutOwnedVPN() throws {
        let data = try JSONEncoder().encode(configuration)
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        json.removeValue(forKey: "ownedVPN")
        let legacy = try JSONDecoder().decode(FirewallConfiguration.self, from: JSONSerialization.data(withJSONObject: json))
        XCTAssertNil(legacy.ownedVPN)
        XCTAssertTrue(legacy.isValid)
        let status = FirewallStatus(state: .protected, detail: "legacy")
        XCTAssertNil(try JSONDecoder().decode(FirewallStatus.self, from: JSONEncoder().encode(status)).policy)
    }
    func testOwnedPacketRulesPassTheActualMacOSPFParserWithoutLoading() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let tunnel = FirewallTunnel(interface: "utun9", addresses: ["10.78.91.2"], identity: "owned")
        for (index, mode) in [(nil, false), (Optional(tunnel), false), (Optional(tunnel), true)].enumerated() {
            let file = directory.appendingPathComponent("\(index).pf")
            try FirewallRules.render(configuration: configuration, tunnel: mode.0, allowTraffic: mode.1).write(to: file, atomically: false, encoding: .utf8)
            try PFDriver().validate(file.path)
        }
    }
}
