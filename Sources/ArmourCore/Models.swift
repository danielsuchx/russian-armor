import Foundation

/// Network availability is diagnostic information, never proof of VPN protection.
public enum Connectivity: String, Codable, Sendable {
    case checking
    case available
    case requiresConnection
    case unavailable

    public var title: String {
        switch self {
        case .checking: return "Проверяется…"
        case .available: return "Подключена"
        case .requiresConnection: return "Требуется подключение"
        case .unavailable: return "Нет подключения"
        }
    }
}

public struct NetworkSnapshot: Equatable, Sendable {
    public let connectivity: Connectivity
    public let availableInterfaces: [String]
    public let checkedAt: Date?

    public init(
        connectivity: Connectivity,
        availableInterfaces: [String] = [],
        checkedAt: Date? = nil
    ) {
        self.connectivity = connectivity
        self.availableInterfaces = Array(Set(availableInterfaces)).sorted()
        self.checkedAt = checkedAt
    }

    public static let checking = NetworkSnapshot(connectivity: .checking)
}

/// This scaffold has no enforcement backend. No network result can promote it
/// to "protected". Add new states only alongside a verified enforcement contract.
public enum ProtectionState: Equatable, Sendable {
    case notConfigured

    public var title: String { "Защита не настроена" }
    public var symbol: String { "shield.slash" }
    public var detail: String {
        "Сетевая блокировка ещё не реализована. Приложение не ограничивает трафик."
    }
    public var canSafelyLaunch: Bool { false }
    public var canPause: Bool { false }
}

public enum VPNLocation: String, CaseIterable, Codable, Sendable {
    case unspecified
    case router
    case thisMac

    public var title: String {
        switch self {
        case .unspecified: return "Не указано"
        case .router: return "На роутере"
        case .thisMac: return "На этом Mac"
        }
    }
}

public struct AppPreferences: Equatable, Codable, Sendable {
    public var showInterfaceNames: Bool
    public var recordNetworkEvents: Bool
    public var vpnLocation: VPNLocation

    public init(
        showInterfaceNames: Bool = true,
        recordNetworkEvents: Bool = true,
        vpnLocation: VPNLocation = .unspecified
    ) {
        self.showInterfaceNames = showInterfaceNames
        self.recordNetworkEvents = recordNetworkEvents
        self.vpnLocation = vpnLocation
    }

    private enum CodingKeys: CodingKey { case showInterfaceNames, recordNetworkEvents, vpnLocation }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        showInterfaceNames = try values.decodeIfPresent(Bool.self, forKey: .showInterfaceNames) ?? true
        recordNetworkEvents = try values.decodeIfPresent(Bool.self, forKey: .recordNetworkEvents) ?? true
        vpnLocation = try values.decodeIfPresent(VPNLocation.self, forKey: .vpnLocation) ?? .unspecified
    }
}

public struct ActivityEvent: Identifiable, Equatable, Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case information
        case network
        case warning
        case sleep
        case wake

        public var symbol: String {
            switch self {
            case .information: return "info.circle"
            case .network: return "network"
            case .warning: return "exclamationmark.triangle"
            case .sleep: return "moon.zzz"
            case .wake: return "sun.max"
            }
        }
    }

    public let id: UUID
    public let date: Date
    public let kind: Kind
    public let title: String
    public let detail: String

    public init(
        id: UUID = UUID(),
        date: Date = Date(),
        kind: Kind = .information,
        title: String,
        detail: String = ""
    ) {
        self.id = id
        self.date = date
        self.kind = kind
        self.title = title
        self.detail = detail
    }
}

/// A bounded local journal. Contains application events, not URLs, IPs or traffic.
public struct EventJournal: Equatable, Codable, Sendable {
    public static let capacity = 100
    public private(set) var events: [ActivityEvent]

    public init(events: [ActivityEvent] = []) {
        self.events = Array(events.prefix(Self.capacity))
    }

    public mutating func record(_ event: ActivityEvent) {
        events.insert(event, at: 0)
        events = Array(events.prefix(Self.capacity))
    }

    public mutating func clear() {
        events.removeAll()
    }

    private enum CodingKeys: CodingKey { case events }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(events: try container.decode([ActivityEvent].self, forKey: .events))
    }
}
