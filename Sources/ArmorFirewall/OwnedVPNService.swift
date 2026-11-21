import ArmorCore
import BoundCurl
import CryptoKit
import Darwin
import Foundation

private struct OwnedVPNRuntime: Codable {
    var interface: String?
    var pid: Int32?
    var started: String?
    let service: String
    let previousDNS: [String]
    let endpoint: String
    let gateway: String
    let physical: String
    var endpointRoute = false
    var splitRoutes: [String] = []
    var probeRoutes: [String] = []
}

private struct OwnedProbeFailure: Error, Sendable {
    let status: Int

    var permitsAuthoritativeRetry: Bool {
        status == 429 || (500...599).contains(status) || status == 0
    }
}

/// This module only operates on the administrator's fixed, root-owned configuration.
/// It never reads shell profiles, ~/.ssh/config, arbitrary executables or user environment.
final class OwnedVPNSession {
    private(set) var child: Process?
    private(set) var tunnel: FirewallTunnel?
    private let configuration: FirewallConfiguration
    private var runtime: OwnedVPNRuntime?

    init(_ configuration: FirewallConfiguration) { self.configuration = configuration }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func save() throws {
        guard let runtime else { throw FirewallError.unsafeFile }
        try RootFiles.write(JSONEncoder().encode(runtime), to: FirewallPaths.vpnRuntime)
    }
    static func processStart(_ pid: Int32) throws -> String {
        try systemCommand("/bin/ps", ["-p", String(pid), "-o", "lstart="]).trimmingCharacters(in: .whitespacesAndNewlines)
    }
    func start(probeOnly: Bool = false) throws {
        guard let own = configuration.ownedVPN, configuration.isValid else { throw FirewallError.invalidConfiguration }
        try Self.restore()
        let core = try RootFiles.read(FirewallPaths.vpnCore, limit: 64 * 1024 * 1024)
        guard Self.digest(core) == own.coreSHA256 else { throw FirewallError.unsafeFile }
        let services = try systemCommand("/usr/sbin/networksetup", ["-listallnetworkservices"])
        guard services.components(separatedBy: .newlines).contains(own.networkService) else { throw FirewallError.invalidConfiguration }
        let dns = try systemCommand("/usr/sbin/networksetup", ["-getdnsservers", own.networkService])
        let previousDNS = dns.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        let savedDNS: [String]
        if previousDNS.allSatisfy(IPRange.isValidAddress) { savedDNS = previousDNS }
        else if dns.contains("There aren't any DNS Servers") { savedDNS = [] }
        else { throw FirewallError.invalidConfiguration }
        let endpoint = configuration.endpoints[0]
        runtime = OwnedVPNRuntime(service: own.networkService, previousDNS: savedDNS,
                                  endpoint: endpoint.address, gateway: own.physicalGateway, physical: configuration.physicalInterface)
        try save() // Recovery journal precedes network changes and the child process.
        _ = try systemCommand("/sbin/route", ["-n", "add", "-host", endpoint.address, own.physicalGateway])
        runtime?.endpointRoute = true; try save()
        try RootFiles.remove(FirewallPaths.vpnInterface)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: FirewallPaths.vpnCore)
        process.arguments = ["-f", "utun"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LOG_LEVEL": "silent",
                               "WG_TUN_NAME_FILE": FirewallPaths.vpnInterface]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); child = process
        runtime?.pid = process.processIdentifier
        runtime?.started = try Self.processStart(process.processIdentifier)
        try save()
        let deadline = Date().addingTimeInterval(5)
        var name: String?
        while Date() < deadline, process.isRunning {
            if let data = try? RootFiles.read(FirewallPaths.vpnInterface) {
                let candidate = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                if FirewallConfiguration.interface(candidate, prefix: "utun") { name = candidate; break }
            }
            usleep(25_000)
        }
        guard let name, process.isRunning else { throw FirewallError.commandFailed("VPN interface") }
        runtime?.interface = name; try save()
        _ = try Self.exchange(interface: name, expectedPID: process.processIdentifier, request: own.request(endpoint: endpoint))
        _ = try systemCommand("/sbin/ifconfig", [name, "inet", own.clientAddress, own.clientAddress, "netmask", "255.255.255.255", "mtu", "1280", "up"])
        for subnet in (probeOnly ? [] : ["0.0.0.0/1", "128.0.0.0/1"]) {
            _ = try systemCommand("/sbin/route", ["-n", "add", "-net", subnet, "-interface", name])
            runtime?.splitRoutes.append(subnet); try save()
        }
        if probeOnly {
            for address in Set(configuration.probeAddresses.values).sorted() {
                _ = try systemCommand("/sbin/route", ["-n", "add", "-host", address, "-interface", name])
                runtime?.probeRoutes.append(address); try save()
            }
        } else {
            _ = try systemCommand("/usr/sbin/networksetup", ["-setdnsservers", own.networkService] + own.dnsServers)
        }
        tunnel = .init(interface: name, addresses: [own.clientAddress],
                       identity: "owned|\(own.coreSHA256)|\(process.processIdentifier)|\(runtime?.started ?? "")|\(name)")
    }
    var isRunning: Bool { child?.isRunning == true && tunnel != nil }
    func lastHandshake() throws -> TimeInterval {
        guard let child, let tunnel, child.isRunning else { throw FirewallError.commandFailed("VPN stopped") }
        let response = try Self.exchange(interface: tunnel.interface, expectedPID: child.processIdentifier, request: "get=1\n\n")
        let seconds = response.components(separatedBy: .newlines).first { $0.hasPrefix("last_handshake_time_sec=") }
            .flatMap { TimeInterval($0.dropFirst("last_handshake_time_sec=".count)) }
        return seconds ?? 0
    }

    /// Only remove routes recorded by this service and still pointing at its own interface.
    /// A restore error leaves PF closed rather than silently opening ordinary Internet access.
    static func restore() throws {
        guard RootFiles.exists(FirewallPaths.vpnRuntime) else { return }
        let runtime = try JSONDecoder().decode(OwnedVPNRuntime.self, from: RootFiles.read(FirewallPaths.vpnRuntime))
        guard FirewallConfiguration.isIPv4(runtime.endpoint), FirewallConfiguration.isIPv4(runtime.gateway),
              FirewallConfiguration.interface(runtime.physical, prefix: "en"),
              !runtime.service.isEmpty, !runtime.service.hasPrefix("-"), !runtime.service.contains("\n"),
              runtime.previousDNS.allSatisfy(IPRange.isValidAddress),
              runtime.interface == nil || FirewallConfiguration.interface(runtime.interface!, prefix: "utun"),
              runtime.probeRoutes.allSatisfy(FirewallConfiguration.isIPv4),
              runtime.splitRoutes.allSatisfy({ ["0.0.0.0/1", "128.0.0.0/1"].contains($0) }) else { throw FirewallError.unsafeFile }
        if let name = runtime.interface {
            for address in runtime.probeRoutes {
                let route = try? systemCommand("/sbin/route", ["-n", "get", address])
                if route?.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == "interface: \(name)" }) == true {
                    _ = try systemCommand("/sbin/route", ["-n", "delete", "-host", address, "-interface", name])
                }
            }
            for subnet in runtime.splitRoutes {
                let destination = subnet.hasPrefix("128") ? "128.0.0.1" : "1.0.0.1"
                let route = try? systemCommand("/sbin/route", ["-n", "get", destination])
                if route?.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == "interface: \(name)" }) == true {
                    _ = try systemCommand("/sbin/route", ["-n", "delete", "-net", subnet, "-interface", name])
                }
            }
        }
        _ = try systemCommand("/usr/sbin/networksetup", ["-setdnsservers", runtime.service] + (runtime.previousDNS.isEmpty ? ["Empty"] : runtime.previousDNS))
        if let pid = runtime.pid, let started = runtime.started,
           (try? processStart(pid)) == started {
            let executable = try systemCommand("/bin/ps", ["-p", String(pid), "-o", "comm="]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard executable == FirewallPaths.vpnCore else { throw FirewallError.unsafeFile }
            guard kill(pid, SIGTERM) == 0 || errno == ESRCH else { throw FirewallError.commandFailed("VPN stop") }
        }
        if runtime.endpointRoute {
            let route = try systemCommand("/sbin/route", ["-n", "get", runtime.endpoint])
            let lines = route.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
            guard lines.contains("gateway: \(runtime.gateway)"), lines.contains("interface: \(runtime.physical)") else { throw FirewallError.incompatiblePF }
            _ = try systemCommand("/sbin/route", ["-n", "delete", "-host", runtime.endpoint, runtime.gateway])
        }
        try RootFiles.remove(FirewallPaths.vpnInterface)
        try RootFiles.remove(FirewallPaths.vpnRuntime)
    }

    /// Root-owned UAPI. Requests/responses can contain private keys: never log them.
    private static func exchange(interface: String, expectedPID: Int32, request: String) throws -> String {
        guard FirewallConfiguration.interface(interface, prefix: "utun"), request.utf8.count < 8192 else { throw FirewallError.unsafeFile }
        let path = "/private/var/run/wireguard/\(interface).sock"
        try RootFiles.checkDirectory("/private/var")
        // macOS ships /var/run as root:daemon 0775. Authenticate the actual
        // root child PID as well as the leaf paths; do not relax RootFiles globally.
        var runInfo = stat(); var directoryInfo = stat()
        guard lstat("/private/var/run", &runInfo) == 0, runInfo.st_mode & S_IFMT == S_IFDIR,
              runInfo.st_uid == 0, runInfo.st_mode & 0o002 == 0,
              (runInfo.st_mode & 0o020 == 0 || runInfo.st_gid == 1),
              lstat("/private/var/run/wireguard", &directoryInfo) == 0,
              directoryInfo.st_mode & S_IFMT == S_IFDIR, directoryInfo.st_uid == 0,
              directoryInfo.st_mode & 0o022 == 0 else { throw FirewallError.unsafeFile }
        var metadata = stat()
        guard lstat(path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFSOCK,
              metadata.st_uid == 0, metadata.st_nlink == 1, metadata.st_mode & 0o077 == 0 else { throw FirewallError.unsafeFile }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw FirewallError.unsafeFile }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        var one: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw FirewallError.unsafeFile }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            bytes.initializeMemory(as: UInt8.self, repeating: 0)
            bytes.copyBytes(from: Array(path.utf8) + [0])
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { throw FirewallError.commandFailed("VPN control socket") }
        var uid: uid_t = 1; var gid: gid_t = 1
        guard getpeereid(fd, &uid, &gid) == 0, uid == 0 else { throw FirewallError.unsafeFile }
        var peerPID: pid_t = 0
        var peerSize = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &peerSize) == 0,
              peerPID == expectedPID else { throw FirewallError.unsafeFile }
        let data = Array(request.utf8)
        var offset = 0
        while offset < data.count {
            let sent = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            if sent < 0 && errno == EINTR { continue }
            guard sent > 0 else { throw FirewallError.commandFailed("VPN control write") }
            offset += sent
        }
        var response = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
        while response.count < 32768 {
            let received = Darwin.read(fd, &buffer, buffer.count)
            if received < 0 && errno == EINTR { continue }
            guard received > 0 else { throw FirewallError.commandFailed("VPN control read") }
            response.append(contentsOf: buffer.prefix(received))
            if response.suffix(2) == Data([10, 10]) { break }
        }
        let text = String(decoding: response, as: UTF8.self)
        guard text.hasSuffix("\n\n"), text.components(separatedBy: .newlines).contains("errno=0") else { throw FirewallError.commandFailed("VPN configuration") }
        return text
    }
}

private actor OwnedProbeBox {
    private var value: (String, Bool)?
    func set(_ identity: String, _ allowed: Bool) { value = (identity, allowed) }
    func take() -> (String, Bool)? { defer { value = nil }; return value }
}

final class OwnedVPNDaemon {
    private let installation = FirewallInstallation()
    private var generation: String?
    private var session: OwnedVPNSession?
    private var health = OwnedVPNHealth()
    private var failures = 0
    private var box = OwnedProbeBox()
    private var probe: Task<Void, Never>?
    private var nextProbe: TimeInterval = 0
    private var kernelRules: String?
    private var applied: String?

    func run() async {
        while !Task.isCancelled {
            do { try await tick() }
            catch {
                probe?.cancel(); probe = nil; box = OwnedProbeBox(); health.reset()
                try? RootFiles.locked {
                    guard try installation.generation() != nil else { return }
                    let configuration = try installation.configuration()
                    let blocked = try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false)
                    try RootFiles.write(Data(blocked.utf8), to: FirewallPaths.anchor)
                    try installation.pf.applyAnchor()
                    try installation.writeStatus(.broken, "Ошибка строгого VPN. Прямой выход остаётся закрыт; требуется восстановление.")
                }
                generation = nil; session = nil; kernelRules = nil; applied = nil
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }
    private func tick() async throws {
        let current = try RootFiles.locked { try installation.generation() }
        guard let current else {
            probe?.cancel(); probe = nil; box = OwnedProbeBox(); health.reset()
            generation = nil; session = nil; kernelRules = nil; applied = nil
            try RootFiles.locked {
                if try installation.generation() == nil { try installation.writeStatus(.disabled, "Строгий VPN выключен.") }
            }
            return
        }
        let configuration = try installation.configuration()
        guard let own = configuration.ownedVPN else { throw FirewallError.invalidConfiguration }
        if generation != current {
            try RootFiles.locked {
                guard try installation.generation() == current else { return }
                try installation.recoverArmed()
                let candidate = OwnedVPNSession(configuration)
                try candidate.start()
                session = candidate; generation = current
            }
            health.reset(); failures = 0; applied = nil; kernelRules = nil; nextProbe = 0
        }
        guard let session, session.isRunning, let tunnel = session.tunnel else { throw FirewallError.commandFailed("VPN stopped") }
        let now = ProcessInfo.processInfo.systemUptime
        if let result = await box.take() {
            probe = nil
            if result.0 == tunnel.identity, result.1 {
                health.confirm(identity: tunnel.identity); failures = 0
            } else { health.reset(); failures = min(failures + 1, 5) }
            nextProbe = now + min(300, 15 * pow(2, Double(failures)))
        }
        let handshake = try session.lastHandshake()
        try RootFiles.locked {
            guard try installation.generation() == current else { return }
            try installation.pf.verifyMain(armed: true)
            try installation.pf.verifyNoTranslations()
            guard try installation.pf.isEnabled() else { throw FirewallError.commandFailed("PF disabled") }
            if let kernelRules {
                guard try installation.pf.command(PFDriver.pfctl, ["-a", FirewallRules.anchor, "-s", "rules"]) == kernelRules else { throw FirewallError.incompatiblePF }
            }
            let allowed = health.permits(identity: tunnel.identity, handshake: handshake, now: Date().timeIntervalSince1970)
            let rules = try FirewallRules.render(configuration: configuration, tunnel: tunnel, allowTraffic: allowed)
            if rules != applied {
                let path = FirewallPaths.directory + "/live.pf"
                try RootFiles.write(Data(rules.utf8), to: path)
                try installation.pf.validate(path)
                _ = try installation.pf.command(PFDriver.pfctl, ["-a", FirewallRules.anchor, "-f", path])
                kernelRules = try installation.pf.command(PFDriver.pfctl, ["-a", FirewallRules.anchor, "-s", "rules"])
                applied = rules
            }
            try installation.writeStatus(allowed ? .protected : .recovering,
                                         allowed ? "Весь Mac: внешний IPv4 только через собственный VPN. Прямой выход и IPv6 закрыты."
                                         : "Прямой выход закрыт. Проверяем выход и защищённое соединение с VPS.", interface: tunnel.interface)
        }
        if probe == nil, !health.isConfirmed(identity: tunnel.identity), now >= nextProbe {
            let box = self.box
            probe = Task.detached(priority: .utility) {
                do {
                    func request(_ host: String, _ path: String, provider: EgressProvider) throws -> EgressObservation {
                        guard let address = configuration.probeAddresses[host] else { throw FirewallError.invalidConfiguration }
                        var bytes = [UInt8](repeating: 0, count: 4096)
                        var length = 0; var status = 0; var retry = 0
                        let result = ra_tunnel_get_resolved("https://\(host)\(path)", tunnel.interface, "\(host):443:\(address)",
                                                            &bytes, bytes.count, &length, &status, &retry) { Task.isCancelled ? 1 : 0 }
                        guard result == RA_OK, status == 200 else { throw OwnedProbeFailure(status: status) }
                        return try EgressObservation.decode(Data(bytes.prefix(length)), provider: provider)
                    }
                    let first = try request("ipwho.is", "/", provider: .ipWhoIS)
                    do {
                        let second = try request("ipinfo.io", "/json", provider: .ipInfo)
                        let allowed = first.ip == own.expectedExitIP && first.ip == second.ip
                            && configuration.rules.evaluateIndependent(
                                ip: first.ip,
                                authoritativeCountry: first.countryCode,
                                secondaryCountry: second.countryCode
                            ).allowed
                        await box.set(tunnel.identity, allowed)
                    } catch let failure as OwnedProbeFailure where failure.permitsAuthoritativeRetry {
                        // IPinfo can rate-limit the root helper. The WireGuard
                        // handshake and pinned exit IP are still mandatory;
                        // retry ipwho.is through the same tunnel as the
                        // authoritative country source instead of leaving the
                        // whole Mac blocked indefinitely on a provider 429.
                        let confirmation = try request("ipwho.is", "/", provider: .ipWhoIS)
                        let allowed = first.ip == own.expectedExitIP && first.ip == confirmation.ip
                            && configuration.rules.evaluate(ip: first.ip, countries: [first.countryCode]).allowed
                        await box.set(tunnel.identity, allowed)
                    }
                } catch { await box.set(tunnel.identity, false) }
            }
        }
    }
}
