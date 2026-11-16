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

/// Protection pauses Claude processes until a fresh egress observation matches the
/// country explicitly trusted by the user.
public enum ProtectionState: Equatable, Sendable {
    case notConfigured
    case setupRequired(String)
    case configuring(String)
    case approvalRequired
    case restartRequired
    case channelEnabled
    case countryConfirmed
    case paused(String)

    public var title: String {
        switch self {
        case .notConfigured: return "Защита недоступна"
        case .setupRequired: return "Нужно подключить защиту"
        case .configuring: return "Включаем защиту…"
        case .approvalRequired: return "Разрешите расширение macOS"
        case .restartRequired: return "Перезагрузите Mac"
        case .channelEnabled: return "Защита включена"
        case .countryConfirmed: return "Контроль страны включён"
        case .paused: return "Защита неактивна"
        }
    }
    public var symbol: String {
        switch self {
        case .channelEnabled: return "shield.fill"
        case .countryConfirmed: return "shield.lefthalf.filled"
        default: return "shield.slash"
        }
    }
    /// Positive status feedback, not permission to claim a protected network route.
    public var isOperational: Bool { self == .channelEnabled || self == .countryConfirmed }
    public var detail: String {
        switch self {
        case .notConfigured:
            return "Системный канал Claude не подключён. Проверка IP сама по себе не защищает соединения."
        case .setupRequired(let message), .configuring(let message): return message
        case .approvalRequired: return "Подтвердите Russian Armour в настройках сетевых расширений macOS."
        case .restartRequired: return "macOS завершит установку расширения после перезагрузки."
        case .channelEnabled:
            return "Системный канал включён. Маршрут существующих соединений требует отдельной проверки."
        case .countryConfirmed:
            return "Смена сети, страны или сбой — пауза Claude. Данные могут уйти до паузы."
        case .paused(let message): return message
        }
    }
    public var canSafelyLaunch: Bool { self == .channelEnabled }
    public var canPause: Bool { self == .channelEnabled }
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
    public var automaticIPChecks: Bool
    public var egressProvider: EgressProvider
    public var allowedCountryCode: String?

    public init(
        showInterfaceNames: Bool = true,
        recordNetworkEvents: Bool = true,
        vpnLocation: VPNLocation = .unspecified,
        automaticIPChecks: Bool = true,
        egressProvider: EgressProvider = .ipWhoIS,
        allowedCountryCode: String? = nil
    ) {
        self.showInterfaceNames = showInterfaceNames
        self.recordNetworkEvents = recordNetworkEvents
        self.vpnLocation = vpnLocation
        self.automaticIPChecks = automaticIPChecks
        self.egressProvider = egressProvider
        self.allowedCountryCode = Self.validCountryCode(allowedCountryCode)
    }

    private enum CodingKeys: CodingKey {
        case showInterfaceNames, recordNetworkEvents, vpnLocation, automaticIPChecks, egressProvider, allowedCountryCode
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        showInterfaceNames = try values.decodeIfPresent(Bool.self, forKey: .showInterfaceNames) ?? true
        recordNetworkEvents = try values.decodeIfPresent(Bool.self, forKey: .recordNetworkEvents) ?? true
        vpnLocation = try values.decodeIfPresent(VPNLocation.self, forKey: .vpnLocation) ?? .unspecified
        automaticIPChecks = try values.decodeIfPresent(Bool.self, forKey: .automaticIPChecks) ?? true
        egressProvider = try values.decodeIfPresent(EgressProvider.self, forKey: .egressProvider) ?? .ipWhoIS
        allowedCountryCode = Self.validCountryCode(try values.decodeIfPresent(String.self, forKey: .allowedCountryCode))
    }

    private static func validCountryCode(_ value: String?) -> String? {
        guard let value, value.utf8.count == 2,
              value.utf8.allSatisfy({ (65...90).contains($0) }) else { return nil }
        return value
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
