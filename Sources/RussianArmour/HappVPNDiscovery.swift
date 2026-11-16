import Foundation
import SystemConfiguration

/// Read-only discovery. A connected profile or interface is not proof of a kill switch.
enum HappVPNDiscovery {
    static let providerIdentifier = "su.ffg.happ.tunnel"

    struct Service: Equatable {
        let id: String
        let provider: String
        let connected: Bool
        let interface: String?
    }

    enum Result: Equatable {
        case unavailable
        case disconnected
        case ambiguous
        case connected(interface: String, isPrimaryIPv4: Bool)
    }

    /// Never guess from a bare utun device or choose between multiple connected profiles.
    static func evaluate(_ services: [Service], primaryService: String?, primaryInterface: String?) -> Result {
        let profiles = services.filter { $0.provider == providerIdentifier }
        guard !profiles.isEmpty else { return .unavailable }
        let active = profiles.filter(\.connected)
        guard !active.isEmpty else { return .disconnected }
        guard active.count == 1 else { return .ambiguous }
        let service = active[0]
        guard let interface = service.interface, isTunnelName(interface) else { return .unavailable }
        return .connected(interface: interface,
                          isPrimaryIPv4: primaryService == service.id && primaryInterface == interface)
    }

    private static func isTunnelName(_ value: String) -> Bool {
        guard value.hasPrefix("utun"), value.utf8.count > 4, value.utf8.count <= 14 else { return false }
        return value.utf8.dropFirst(4).allSatisfy { (48...57).contains($0) }
    }

    static func read() -> Result {
        guard let store = SCDynamicStoreCreate(nil, "Russian Armour Happ discovery" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "Setup:/Network/Service/.*/VPN" as CFString) as? [String] else {
            return .unavailable
        }
        let prefix = "Setup:/Network/Service/"
        let suffix = "/VPN"
        var services: [Service] = []
        for key in keys where key.hasPrefix(prefix) && key.hasSuffix(suffix) {
            guard let setup = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let provider = setup["NEProviderBundleIdentifier"] as? String,
                  provider == providerIdentifier else { continue }
            let id = String(key.dropFirst(prefix.count).dropLast(suffix.count))
            guard let connection = SCNetworkConnectionCreateWithServiceID(nil, id as CFString, nil, nil) else {
                return .unavailable
            }
            let status = SCNetworkConnectionGetStatus(connection)
            let stateKey = "State:/Network/Service/\(id)/IPv4"
            let ipv4 = SCDynamicStoreCopyValue(store, stateKey as CFString) as? [String: Any]
            services.append(Service(id: id, provider: provider,
                                    connected: status == .connected,
                                    interface: ipv4?["InterfaceName"] as? String))
        }
        let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
        return evaluate(services, primaryService: global?["PrimaryService"] as? String,
                        primaryInterface: global?["PrimaryInterface"] as? String)
    }
}
