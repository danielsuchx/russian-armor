import Foundation

/// Administrator-installed, root-owned. Private material is never part of status or diagnostic exports.
public struct OwnedVPNConfiguration: Codable, Equatable, Sendable {
    public let privateKey: String
    public let peerPublicKey: String
    public let clientAddress: String
    public let expectedExitIP: String
    public let physicalGateway: String
    public let networkService: String
    public let dnsServers: [String]
    public let coreSHA256: String

    public init(privateKey: String, peerPublicKey: String, clientAddress: String, expectedExitIP: String,
                physicalGateway: String, networkService: String, dnsServers: [String], coreSHA256: String) {
        self.privateKey = privateKey; self.peerPublicKey = peerPublicKey; self.clientAddress = clientAddress
        self.expectedExitIP = expectedExitIP; self.physicalGateway = physicalGateway
        self.networkService = networkService; self.dnsServers = dnsServers; self.coreSHA256 = coreSHA256
    }
    public var isValid: Bool {
        [privateKey, peerPublicKey].allSatisfy { Data(base64Encoded: $0)?.count == 32 }
        && [clientAddress, expectedExitIP, physicalGateway].allSatisfy(FirewallConfiguration.isIPv4)
        && !networkService.isEmpty && networkService.utf8.count <= 80
        && !networkService.contains("\n") && !networkService.contains("\0")
        && !dnsServers.isEmpty && dnsServers.count <= 4 && dnsServers.allSatisfy(FirewallConfiguration.isIPv4)
        && coreSHA256.count == 64 && coreSHA256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    /// WireGuard UAPI uses hexadecimal keys, not shell arguments or log output.
    public func request(endpoint: VPNEndpoint) throws -> String {
        guard isValid, endpoint.isValid, endpoint.transport == "udp" else { throw FirewallError.invalidConfiguration }
        func hex(_ text: String) -> String { Data(base64Encoded: text)!.map { String(format: "%02x", $0) }.joined() }
        return "set=1\nprivate_key=\(hex(privateKey))\nreplace_peers=true\npublic_key=\(hex(peerPublicKey))\nendpoint=\(endpoint.address):\(endpoint.port)\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n\n"
    }
}

/// Encryption peer liveness is distinct from a GeoIP API's availability.
/// A new child/interface needs a fresh two-source egress check. Thereafter the
/// pinned peer's authenticated WireGuard handshakes maintain VPN liveness.
public struct OwnedVPNHealth: Sendable {
    private var identity: String?
    public init() {}
    public mutating func confirm(identity: String) { self.identity = identity }
    public mutating func reset() { identity = nil }
    public func isConfirmed(identity: String) -> Bool { self.identity == identity }
    public func permits(identity: String, handshake: TimeInterval, now: TimeInterval) -> Bool {
        self.identity == identity && handshake > 0 && (0...180).contains(now - handshake)
    }
}
