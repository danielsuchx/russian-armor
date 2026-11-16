import Foundation

public struct LocalInterface: Equatable, Sendable {
    public let name: String
    public let isUp: Bool

    public init(name: String, isUp: Bool) {
        self.name = name
        self.isUp = isUp
    }
}

/// An up utun interface is a local observation, not proof of VPN routing.
/// Apple services can also create utun interfaces; proxy-only VPNs may create none.
public enum TunnelObservation: Equatable, Sendable {
    case notChecked
    case observed([String])
    case unavailable

    public static func inspect(_ interfaces: [LocalInterface]) -> Self {
        let names = interfaces.filter { item in
            guard item.isUp, item.name.hasPrefix("utun") else { return false }
            let suffix = item.name.dropFirst(4)
            return !suffix.isEmpty && suffix.utf8.allSatisfy { (48...57).contains($0) }
        }.map(\.name)
        return .observed(Array(Set(names)).sorted { $0.localizedStandardCompare($1) == .orderedAscending })
    }

    public var title: String {
        switch self {
        case .notChecked: return "Проверяются…"
        case .observed(let names) where names.isEmpty: return "Не обнаружены"
        case .observed(let names): return names.count == 1 ? "Обнаружен · 1" : "Обнаружены · \(names.count)"
        case .unavailable: return "Не удалось проверить"
        }
    }

    public var interfaceNames: [String] {
        if case .observed(let names) = self { return names }
        return []
    }
}

/// Discovery by bundle identifier only. Never an authorization identity or a count
/// of Claude Code sessions, and never used to stop a process or grant network access.
public enum ApplicationPresence: Equatable, Sendable {
    case notChecked
    case notInstalled
    case notRunning
    case running

    public var title: String {
        switch self {
        case .notChecked: return "Проверяется…"
        case .notInstalled: return "Не найден"
        case .notRunning: return "Не запущен"
        case .running: return "Открыт"
        }
    }
}

public struct LocalDiagnosticsSnapshot: Equatable, Sendable {
    public let tunnels: TunnelObservation
    public let claudeDesktop: ApplicationPresence
    public let checkedAt: Date?

    public init(
        tunnels: TunnelObservation,
        claudeDesktop: ApplicationPresence,
        checkedAt: Date? = nil
    ) {
        self.tunnels = tunnels
        self.claudeDesktop = claudeDesktop
        self.checkedAt = checkedAt
    }

    public static let notChecked = LocalDiagnosticsSnapshot(tunnels: .notChecked, claudeDesktop: .notChecked)
}
