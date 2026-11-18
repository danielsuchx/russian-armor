import ArmorCore
import Darwin
import Foundation
import Network
import Security

public struct VerifiedTunnel: Codable, Equatable, Sendable {
    public let interface: String
    public let owner: ProtectedProcessIdentity
    public let teamID: String
    public let signingID: String
    public let sourceAddresses: [String]
    public init(interface: String, owner: ProtectedProcessIdentity, teamID: String, signingID: String, sourceAddresses: [String]) {
        self.interface = interface; self.owner = owner; self.teamID = teamID
        self.signingID = signingID; self.sourceAddresses = sourceAddresses
    }
    public var ownerKey: String {
        teamID.isEmpty ? "github:hiddify/hiddify-app/" + signingID : teamID + "/" + signingID
    }
    public var title: String { "\(signingID) · \(interface)" }
}

public enum TunnelCheckError: Error, LocalizedError {
    case unavailable, readerUnavailable, ambiguous, changed, invalidHTTP
    public var errorDescription: String? {
        switch self {
        case .unavailable: return "Не удалось подтвердить владельца локального туннеля. Проверка через обычную сеть не выполняется."
        case .readerUnavailable: return "Служба чтения туннелей не ответила. В «Настройки → Защита» нажмите «Переподключить службу»."
        case .ambiguous: return "Найдено несколько туннелей. Выберите владельца VPN в настройках."
        case .changed: return "Туннель изменился во время проверки. Нужна новая серия."
        case .invalidHTTP: return "Проверка через туннель вернула неподдерживаемый HTTP-ответ."
        }
    }
}

/// Unreadable system-owned providers are deliberately not inferred
/// from the mere presence of an utun interface. A signed owner is evidence of
/// identity, not a claim that the vendor or its tunnel is trustworthy.
public enum TunnelOwnershipReader {
    public static func read() throws -> [VerifiedTunnel] {
        var tunnels = try scan(privilegedProvidersOnly: false)
        if geteuid() != 0, ClashTunnelService.isEnabled {
            let privileged = try ClashTunnelService.read()
            for tunnel in privileged where !tunnels.contains(tunnel) {
                tunnels.append(tunnel)
            }
        }
        return tunnels
    }

    /// Only explicitly supported providers can be inspected through the system service.
    public static func readPrivilegedProviders() throws -> [VerifiedTunnel] {
        guard geteuid() == 0 else { throw TunnelCheckError.unavailable }
        return try scan(privilegedProvidersOnly: true)
    }

    private static func scan(privilegedProvidersOnly: Bool) throws -> [VerifiedTunnel] {
        let deadline = ProcessInfo.processInfo.systemUptime + 1.5
        var addresses: [String: [String]] = [:]
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { throw TunnelCheckError.unavailable }
        if let first {
            defer { freeifaddrs(first) }
            var cursor: UnsafeMutablePointer<ifaddrs>? = first
            while let entry = cursor?.pointee {
                defer { cursor = entry.ifa_next }
                let name = String(cString: entry.ifa_name)
                guard name.hasPrefix("utun"), Int32(entry.ifa_flags) & IFF_UP != 0,
                      let address = entry.ifa_addr, [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)) else { continue }
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let value = String(cString: host)
                    // Scoped IPv6 link-local addresses are not usable as PF literals.
                    if !value.contains("%") { addresses[name, default: []].append(value) }
                }
            }
        }
        guard !addresses.isEmpty else { return [] }
        var pids = [Int32](repeating: 0, count: 4096)
        let bytes = pids.withUnsafeMutableBytes { proc_listpids(UInt32(PROC_ALL_PIDS), 0, $0.baseAddress, Int32($0.count)) }
        guard bytes > 0, Int(bytes) < pids.count * MemoryLayout<Int32>.size else { throw TunnelCheckError.unavailable }
        var found: [VerifiedTunnel] = []
        for pid in pids.prefix(Int(bytes) / MemoryLayout<Int32>.size) where pid > 1 {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw TunnelCheckError.unavailable }
            guard let process = processInfo(pid) else { continue }
            // Filter before examining descriptors in the privileged service.
            var provider: TunnelProvider?
            if privilegedProvidersOnly {
                guard let candidate = candidateProvider(pid, uid: process.uid) else { continue }
                provider = candidate
            }
            var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: 4097)
            let count = descriptors.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
            guard count > 0, Int(count) < descriptors.count * MemoryLayout<proc_fdinfo>.size else { continue }
            var names = Set<String>()
            for descriptor in descriptors.prefix(Int(count) / MemoryLayout<proc_fdinfo>.size) where descriptor.proc_fdtype == PROX_FDTYPE_SOCKET {
                var socket = socket_fdinfo()
                guard proc_pidfdinfo(pid, descriptor.proc_fd, PROC_PIDFDSOCKETINFO, &socket, Int32(MemoryLayout<socket_fdinfo>.size)) == MemoryLayout<socket_fdinfo>.size,
                      socket.psi.soi_kind == SOCKINFO_KERN_CTL else { continue }
                var control = socket.psi.soi_proto.pri_kern_ctl
                let controlName = withUnsafeBytes(of: &control.kcsi_name) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
                if let name = interface(controlName: controlName, unit: control.kcsi_unit), addresses[name] != nil { names.insert(name) }
            }
            guard !names.isEmpty else { continue }
            if !privilegedProvidersOnly { provider = candidateProvider(pid, uid: process.uid) }
            guard let signature = signature(pid, provider: provider),
                  let after = processInfo(pid), after == process else { continue }
            for name in names.sorted() {
                found.append(VerifiedTunnel(interface: name, owner: process.identity, teamID: signature.team,
                                            signingID: signature.identifier, sourceAddresses: addresses[name, default: []].sorted()))
            }
        }
        return found
    }

    public static func select(_ tunnels: [VerifiedTunnel], ownerKey: String?) throws -> VerifiedTunnel {
        let matching = tunnels.filter { ownerKey == nil || $0.ownerKey == ownerKey }
        guard !matching.isEmpty else { throw TunnelCheckError.unavailable }
        guard matching.count == 1 else { throw TunnelCheckError.ambiguous }
        return matching[0]
    }

    static func interface(controlName: String, unit: UInt32) -> String? {
        guard controlName == "com.apple.net.utun_control", unit > 0 else { return nil }
        return "utun\(unit - 1)"
    }

    private static func candidateProvider(_ pid: Int32, uid: uid_t) -> TunnelProvider? {
        var path = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        return TunnelProvider.candidate(executable: String(cString: path), uid: uid)
    }

    private static func processInfo(_ pid: Int32) -> (identity: ProtectedProcessIdentity, uid: uid_t)? {
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return (.init(pid: pid, startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec), info.pbi_uid)
    }

    private static func signature(_ pid: Int32, provider: TunnelProvider?) -> (team: String, identifier: String)? {
        var requirement: SecRequirement?
        if let expression = provider?.requirement {
            guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess, requirement != nil else { return nil }
        }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return nil }
        var information: CFDictionary?
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String, !identifier.isEmpty else { return nil }
        let team = values[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        guard !team.isEmpty || provider == .hiddifyService else { return nil }
        return (team, identifier)
    }
}
