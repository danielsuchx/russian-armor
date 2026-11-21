import Foundation

public enum FirewallError: Error, LocalizedError {
    case invalidConfiguration, incompatiblePF, commandFailed(String), unsafeFile, requiresRoot
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Некорректная конфигурация kill switch. Нужны числовые IPv4, точные порты, физический интерфейс и владелец VPN."
        case .incompatiblePF: return "Конфигурация pf отличается от поддерживаемой. Автоматическое изменение отменено."
        case .commandFailed(let command): return "Не удалось выполнить системную операцию: \(command). Состояние защиты не подтверждено."
        case .unsafeFile: return "Небезопасные права, тип или размер системного файла. Операция отменена."
        case .requiresRoot: return "Эта операция требует явного запуска установленного helper через sudo."
        }
    }
}

public struct VPNEndpoint: Codable, Equatable, Sendable {
    public let address: String
    public let port: UInt16
    public let transport: String
    public init(address: String, port: UInt16, transport: String) {
        self.address = address; self.port = port; self.transport = transport
    }
    public var isValid: Bool { FirewallConfiguration.isIPv4(address) && port > 0 && ["tcp", "udp"].contains(transport) }
}

/// Separate root-owned policy: changing GUI preferences cannot broaden this policy.
public struct FirewallConfiguration: Codable, Equatable, Sendable {
    public let version: Int
    public let physicalInterface: String
    public let vpnOwnerKey: String
    public let endpoints: [VPNEndpoint]
    public let probeAddresses: [String: String]
    public let rules: AccessRules
    public let ownedVPN: OwnedVPNConfiguration?

    public init(version: Int = 1, physicalInterface: String, vpnOwnerKey: String,
                endpoints: [VPNEndpoint], probeAddresses: [String: String], rules: AccessRules,
                ownedVPN: OwnedVPNConfiguration? = nil) {
        self.version = version; self.physicalInterface = physicalInterface; self.vpnOwnerKey = vpnOwnerKey
        self.endpoints = endpoints; self.probeAddresses = probeAddresses; self.rules = rules
        self.ownedVPN = ownedVPN
    }
    public var isValid: Bool {
        let owner = vpnOwnerKey.split(separator: "/", omittingEmptySubsequences: false)
        return version == 1 && Self.interface(physicalInterface, prefix: "en")
            && owner.count == 2 && owner.allSatisfy { !$0.isEmpty && $0.count <= 200 && $0.utf8.allSatisfy { (33...126).contains($0) } }
            && !endpoints.isEmpty && endpoints.count <= 16 && endpoints.allSatisfy(\.isValid)
            && Set(probeAddresses.keys) == ["ipwho.is", "ipinfo.io"] && probeAddresses.values.allSatisfy(Self.isIPv4)
            && rules.isValid && !rules.allowedCountries.isEmpty
            && (ownedVPN == nil || (ownedVPN!.isValid && endpoints.count == 1 && endpoints[0].transport == "udp"))
    }
    public static func interface(_ text: String, prefix: String) -> Bool {
        let suffix = text.dropFirst(prefix.count)
        return text.hasPrefix(prefix) && !suffix.isEmpty && suffix.count <= 6 && suffix.utf8.allSatisfy { (48...57).contains($0) }
    }
    public static func isIPv4(_ text: String) -> Bool {
        guard !text.contains(":"), !text.contains("/"), let range = IPRange(text) else { return false }
        return range.value == text && text != "0.0.0.0" && !text.hasPrefix("127.")
    }
}

public struct FirewallTunnel: Equatable, Sendable {
    public let interface: String
    public let addresses: [String]
    public let identity: String
    public init(interface: String, addresses: [String], identity: String) {
        self.interface = interface; self.addresses = addresses; self.identity = identity
    }
    public var isValid: Bool {
        FirewallConfiguration.interface(interface, prefix: "utun") && !addresses.isEmpty && addresses.count <= 32
            && addresses.allSatisfy { IPRange.isValidAddress($0) && !$0.contains("%") && !$0.contains("/") }
    }
}

public enum FirewallRules {
    public static let anchor = "app.russian-armor"
    public static let anchorFile = "/etc/pf.anchors/app.russian-armor"
    public static let mainReference = "anchor \"app.russian-armor\" quick\n"
    public static let loadReference = "load anchor \"app.russian-armor\" from \"/etc/pf.anchors/app.russian-armor\"\n"

    /// No floating PF states: every packet must still match the selected tunnel.
    /// This anchor must precede the Apple filtering anchor in the main ruleset.
    public static func render(configuration: FirewallConfiguration, tunnel: FirewallTunnel?, allowTraffic: Bool) throws -> String {
        guard configuration.isValid, tunnel?.isValid != false, !allowTraffic || tunnel != nil else { throw FirewallError.invalidConfiguration }
        var lines = ["# Russian Armor: whole-Mac egress guard", "pass quick on lo0 all no state"]
        let physical = configuration.physicalInterface
        let bootstrapUser = configuration.ownedVPN == nil ? "" : " user 0"
        // IPv4 network renewal only; no general LAN, DNS, captive portal or IPv6 exception.
        lines += ["pass out quick on \(physical) inet proto udp from any port 68 to 255.255.255.255 port 67\(bootstrapUser) no state",
                  "pass in quick on \(physical) inet proto udp from any port 67 to any port 68 no state"]
        for endpoint in configuration.endpoints {
            let flags = endpoint.transport == "tcp" ? " flags any" : ""
            lines += ["pass out quick on \(physical) inet proto \(endpoint.transport) from any to \(endpoint.address) port \(endpoint.port)\(bootstrapUser)\(flags) no state",
                      "pass in quick on \(physical) inet proto \(endpoint.transport) from \(endpoint.address) port \(endpoint.port) to any\(flags) no state"]
        }
        if let tunnel {
            for address in tunnel.addresses.sorted() {
                // IPv6 egress geography is not independently checked yet. Keep
                // IPv6 blocked even on the VPN instead of extending IPv4 trust.
                guard !address.contains(":") else { continue }
                let family = "inet"
                if allowTraffic {
                    lines += ["pass out quick on \(tunnel.interface) \(family) from \(address) to any no state",
                              "pass in quick on \(tunnel.interface) \(family) from any to \(address) no state"]
                } else if family == "inet" {
                    // Probes have numeric destinations, TLS still validates the provider hostname.
                    for destination in Set(configuration.probeAddresses.values).sorted() {
                        lines += ["pass out quick on \(tunnel.interface) inet proto tcp from \(address) to \(destination) port 443 user 0 flags any no state",
                                  "pass in quick on \(tunnel.interface) inet proto tcp from \(destination) port 443 to \(address) flags any no state"]
                    }
                }
            }
        }
        lines += ["block drop quick all"]
        return lines.joined(separator: "\n") + "\n"
    }

    public static func installing(in original: String) throws -> String {
        let lines = original.components(separatedBy: "\n")
        guard statements(original) == statements(stockConfiguration),
              lines.filter({ $0 == "anchor \"com.apple/*\"" }).count == 1 else { throw FirewallError.incompatiblePF }
        return lines.map { $0 == "anchor \"com.apple/*\"" ? mainReference + $0 : $0 }.joined(separator: "\n") + loadReference
    }
    public static func statements(_ text: String) -> [String] {
        text.components(separatedBy: .newlines).map { $0.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0].trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
    public static let stockConfiguration = """
    scrub-anchor "com.apple/*"
    nat-anchor "com.apple/*"
    rdr-anchor "com.apple/*"
    dummynet-anchor "com.apple/*"
    anchor "com.apple/*"
    load anchor "com.apple" from "/etc/pf.anchors/com.apple"
    """ + "\n"
}

/// Pure state machine. Call with monotonic uptime, never wall-clock time.
public struct FirewallRecovery: Sendable {
    private var recovery = RecoveryGate()
    private var identity: String?
    public private(set) var validUntil: TimeInterval = 0
    public var successes: Int { recovery.successes }
    public init() {}
    public mutating func reset() { recovery.reset(); identity = nil; validUntil = 0 }
    public mutating func observe(tunnel: FirewallTunnel, ip: String, countries: Set<String>, allowed: Bool, now: TimeInterval) {
        guard allowed, tunnel.isValid else { reset(); return }
        if identity != tunnel.identity || now >= validUntil { reset(); identity = tunnel.identity }
        recovery.observe(ip: ip, countries: countries, at: Date(timeIntervalSince1970: now))
        validUntil = now + 30
    }
    public func permits(_ tunnel: FirewallTunnel, now: TimeInterval) -> Bool {
        recovery.isReady && identity == tunnel.identity && now < validUntil
    }
}

public struct FirewallStatus: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable { case disabled, blocked, recovering, protected, broken }
    public let state: State
    public let updatedAt: Date
    public let detail: String
    public let interface: String?
    public let policy: String?
    public init(state: State, updatedAt: Date = Date(), detail: String, interface: String? = nil, policy: String? = nil) {
        self.state = state; self.updatedAt = updatedAt; self.detail = detail; self.interface = interface
        self.policy = policy
    }
    public func isFresh(at date: Date) -> Bool { (0...6).contains(date.timeIntervalSince(updatedAt)) }
}
