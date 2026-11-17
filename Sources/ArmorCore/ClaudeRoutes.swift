import Foundation

/// Observations of real process sockets and the OS route to their peers, not proof
/// of packet forwarding or of the public address after a proxy/router.
public struct ClaudeConnectionRoute: Equatable, Identifiable, Sendable {
    public enum Path: Equatable, Sendable {
        case localPeer
        case tunnel(interface: String)
        case outsideTunnel(interface: String)
        case unknown
    }

    public let connection: TrafficConnection
    public let sourceInterfaces: [String]
    public let routeInterface: String?
    public let path: Path
    public var id: TrafficConnection.ID { connection.id }

    public init(connection: TrafficConnection, sourceInterfaces: [String], routeInterface: String?) {
        self.connection = connection
        self.sourceInterfaces = sourceInterfaces.sorted()
        self.routeInterface = routeInterface
        if Self.isLocalPeer(connection.remote) {
            path = .localPeer
        } else if let routeInterface {
            // A tunnel in the routing table alone is insufficient: an established
            // socket can still have a source address from the pre-VPN network.
            if Self.isTunnel(routeInterface), !sourceInterfaces.isEmpty,
               sourceInterfaces.allSatisfy({ $0 == routeInterface }) {
                path = .tunnel(interface: routeInterface)
            } else if !Self.isTunnel(routeInterface) || sourceInterfaces.contains(where: { !Self.isTunnel($0) }) {
                path = .outsideTunnel(interface: routeInterface)
            } else {
                path = .unknown
            }
        } else {
            path = .unknown
        }
    }

    public var title: String {
        switch path {
        case .localPeer: return "Локальный узел · дальнейший выход неизвестен"
        case .tunnel(let interface): return "Источник и маршрут ОС: туннель \(interface)"
        case .outsideTunnel(let interface): return "Источник или маршрут ОС вне туннеля · \(interface)"
        case .unknown: return "Маршрут не определён"
        }
    }

    private static func isTunnel(_ name: String) -> Bool {
        ["utun", "ipsec", "ppp", "tun", "tap"].contains { prefix in
            name.hasPrefix(prefix) && !name.dropFirst(prefix.count).isEmpty
                && name.dropFirst(prefix.count).allSatisfy(\.isNumber)
        }
    }

    private static func isLocalPeer(_ endpoint: TrafficEndpoint) -> Bool {
        if endpoint.isLoopback { return true }
        if endpoint.version == .v6 {
            let address = endpoint.address.lowercased()
            if address.hasPrefix("::ffff:") {
                return isLocalPeer(.init(address: String(address.dropFirst(7)), port: endpoint.port, version: .v4))
            }
            // ULA, link-local and multicast are not evidence of an Internet path.
            return address.hasPrefix("fc") || address.hasPrefix("fd")
                || ["fe8", "fe9", "fea", "feb", "ff"].contains { address.hasPrefix($0) }
        }
        let bytes = endpoint.address.split(separator: ".").compactMap { UInt8($0) }
        guard bytes.count == 4 else { return false }
        return bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 0
            || (bytes[0] == 172 && (16...31).contains(bytes[1]))
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] == 100 && (64...127).contains(bytes[1]))
            || bytes[0] >= 224
    }
}

public struct ClaudeRouteSnapshot: Equatable, Sendable {
    public let routes: [ClaudeConnectionRoute]
    public let capturedAt: Date
    public let isPartial: Bool

    public init(routes: [ClaudeConnectionRoute], capturedAt: Date = Date(), isPartial: Bool = false) {
        self.routes = Array(routes.prefix(TrafficSnapshot.capacity))
        self.capturedAt = capturedAt
        self.isPartial = isPartial || routes.count > TrafficSnapshot.capacity
    }

    /// nil means no *observed* contradiction, never a verified public egress IP.
    public func pauseReason(vpnLocation: VPNLocation) -> String? {
        if isPartial {
            return "Не все соединения Claude удалось прочитать. Ждём полный снимок."
        }
        if routes.contains(where: { $0.path == .unknown }) {
            return "Не удалось определить маршрут внешнего соединения Claude."
        }
        if vpnLocation == .thisMac, routes.contains(where: {
            if case .outsideTunnel = $0.path { return true }
            return false
        }) {
            return "У Claude обнаружен внешний источник или маршрут вне локального туннеля. Проверьте VPN на Mac."
        }
        return nil
    }
}
