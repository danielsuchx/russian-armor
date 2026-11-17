import Darwin
import Foundation

public enum ProtectedApplication: String, Codable, CaseIterable, Sendable {
    case desktop, code
    public var title: String { self == .desktop ? "Claude Desktop" : "Claude Code" }
}

/// Numeric addresses only. IPv4-mapped IPv6 is normalized so an IPv4 deny cannot
/// be bypassed by a different textual representation. No DNS or zone identifiers.
public struct IPRange: Equatable, Codable, Sendable {
    public let value: String
    private let network: [UInt8]
    private let prefix: Int

    public init?(_ text: String) {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), let address = Self.address(String(parts[0])) else { return nil }
        var bits = address.bytes.count * 8
        if address.mapped { bits = 32 }
        if parts.count == 2 {
            guard !parts[1].isEmpty, parts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
                  let parsed = Int(parts[1]) else { return nil }
            bits = parsed
            if address.mapped {
                guard (96...128).contains(bits) else { return nil }
                bits -= 96
            }
        }
        guard (0...(address.bytes.count * 8)).contains(bits) else { return nil }
        prefix = bits
        let masked = Self.mask(address.bytes, bits: bits)
        network = masked
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let rendered = masked.withUnsafeBytes {
            inet_ntop(masked.count == 4 ? AF_INET : AF_INET6, $0.baseAddress, &buffer, socklen_t(buffer.count))
        }
        guard rendered != nil else { return nil }
        value = String(cString: buffer) + (parts.count == 2 ? "/\(bits)" : "")
    }

    public func contains(_ address: String) -> Bool {
        guard let parsed = Self.address(address), parsed.bytes.count == network.count else { return false }
        return Self.mask(parsed.bytes, bits: prefix) == network
    }

    public static func isValidAddress(_ value: String) -> Bool { address(value) != nil }

    private static func address(_ text: String) -> (bytes: [UInt8], mapped: Bool)? {
        guard !text.isEmpty, !text.contains("%"), !text.contains("\0") else { return nil }
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return (withUnsafeBytes(of: &v4) { Array($0) }, false)
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, text, &v6) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
            return (Array(bytes.suffix(4)), true)
        }
        return (bytes, false)
    }

    private static func mask(_ bytes: [UInt8], bits: Int) -> [UInt8] {
        bytes.enumerated().map { index, byte in
            let remaining = bits - index * 8
            if remaining >= 8 { return byte }
            if remaining <= 0 { return 0 }
            return byte & (UInt8.max << (8 - remaining))
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let range = IPRange(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid IP or CIDR")
        }
        self = range
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

public struct AccessDecision: Equatable, Sendable {
    public let allowed: Bool
    /// Contains rule category/country only, never a literal IP or CIDR.
    public let explanation: String
}

public struct AccessRules: Equatable, Codable, Sendable {
    public var allowedCountries: Set<String>
    public var deniedCountries: Set<String>
    public var allowedIPs: [IPRange]
    public var deniedIPs: [IPRange]

    public init(allowedCountries: Set<String> = [], deniedCountries: Set<String> = [],
                allowedIPs: [IPRange] = [], deniedIPs: [IPRange] = []) {
        self.allowedCountries = allowedCountries
        self.deniedCountries = deniedCountries
        self.allowedIPs = allowedIPs
        self.deniedIPs = deniedIPs
    }

    public var isValid: Bool {
        let codes = allowedCountries.union(deniedCountries)
        return codes.allSatisfy { $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } }
            && codes.count <= 250 && allowedIPs.count <= 128 && deniedIPs.count <= 128
    }

    public func evaluate(ip: String?, countries: Set<String>) -> AccessDecision {
        func deny(_ text: String) -> AccessDecision { .init(allowed: false, explanation: text) }
        guard isValid else { return deny("Правила повреждены или содержат некорректные значения.") }
        guard let ip, IPRange.isValidAddress(ip), !countries.isEmpty,
              countries.allSatisfy({ $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } }) else {
            return deny("IP или страна не подтверждены.")
        }
        if !countries.isDisjoint(with: deniedCountries) { return deny("Страна входит в список запретов.") }
        if deniedIPs.contains(where: { $0.contains(ip) }) { return deny("IP входит в запрещённый адрес или диапазон.") }
        guard !allowedCountries.isEmpty else { return deny("Не выбраны разрешённые страны.") }
        guard countries.isSubset(of: allowedCountries) else {
            return deny("Не все страны из ответа сервисов разрешены: \(countries.sorted().joined(separator: ", ")).")
        }
        if !allowedIPs.isEmpty, !allowedIPs.contains(where: { $0.contains(ip) }) {
            return deny("IP не входит в разрешённые адреса и диапазоны.")
        }
        return .init(allowed: true, explanation: allowedIPs.isEmpty
                     ? "Страна разрешена; явных запретов нет."
                     : "Страна и IP разрешены; явных запретов нет.")
    }
}

public struct AccessProfile: Equatable, Identifiable, Codable, Sendable {
    public var id: UUID
    public var name: String
    public var sharedRules: AccessRules
    public var separateApplications: Bool
    public var desktopRules: AccessRules
    public var codeRules: AccessRules

    public init(id: UUID = UUID(), name: String = "Основной", sharedRules: AccessRules = .init(),
                separateApplications: Bool = false, desktopRules: AccessRules? = nil, codeRules: AccessRules? = nil) {
        self.id = id
        self.name = name
        self.sharedRules = sharedRules
        self.separateApplications = separateApplications
        self.desktopRules = desktopRules ?? sharedRules
        self.codeRules = codeRules ?? sharedRules
    }

    public func rules(for application: ProtectedApplication) -> AccessRules {
        separateApplications ? (application == .desktop ? desktopRules : codeRules) : sharedRules
    }
    public var isValid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && name.count <= 60
            && !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
            && sharedRules.isValid && desktopRules.isValid && codeRules.isValid
    }
}

public struct AccessConfiguration: Equatable, Codable, Sendable {
    public var profiles: [AccessProfile]
    public var activeProfileID: UUID
    public var activeProfile: AccessProfile? { profiles.first { $0.id == activeProfileID } }
    public var isValid: Bool {
        !profiles.isEmpty && profiles.count <= 20 && Set(profiles.map(\.id)).count == profiles.count
            && profiles.allSatisfy(\.isValid) && activeProfile != nil
    }

    public init(profiles: [AccessProfile], activeProfileID: UUID) {
        self.profiles = profiles
        self.activeProfileID = activeProfileID
    }

    public static func migrating(country: String?) -> AccessConfiguration {
        let rules = AccessRules(allowedCountries: Set(country.map { [$0] } ?? []))
        let profile = AccessProfile(id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, sharedRules: rules)
        return .init(profiles: [profile], activeProfileID: profile.id)
    }
}
