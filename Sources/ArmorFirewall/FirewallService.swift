import ArmorCore
import ArmorTunnel
import Darwin
import Foundation

struct PFEnableReference: Codable {
    let bootSeconds: Int
    let bootMicroseconds: Int
    let token: String
    static func bootTime() throws -> timeval {
        var value = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &value, &size, nil, 0) == 0 else { throw FirewallError.unsafeFile }
        return value
    }
}

struct FirewallInstallation {
    var pf = PFDriver()
    private var referencePath: String { FirewallPaths.directory + "/pf-reference.json" }

    func ensureReference() throws {
        let boot = try PFEnableReference.bootTime()
        if RootFiles.exists(referencePath) {
            let reference = try JSONDecoder().decode(PFEnableReference.self, from: RootFiles.read(referencePath))
            if reference.bootSeconds == boot.tv_sec && reference.bootMicroseconds == boot.tv_usec, try pf.isEnabled() { return }
        }
        let token = try pf.acquireReference()
        let reference = PFEnableReference(bootSeconds: boot.tv_sec, bootMicroseconds: Int(boot.tv_usec), token: token)
        try RootFiles.write(JSONEncoder().encode(reference), to: referencePath)
    }
    func releaseReference() throws {
        guard RootFiles.exists(referencePath) else { return }
        let reference = try JSONDecoder().decode(PFEnableReference.self, from: RootFiles.read(referencePath))
        let boot = try PFEnableReference.bootTime()
        if reference.bootSeconds == boot.tv_sec && reference.bootMicroseconds == boot.tv_usec {
            try pf.releaseReference(reference.token)
        }
        try RootFiles.remove(referencePath)
    }

    func configuration() throws -> FirewallConfiguration {
        let value = try JSONDecoder().decode(FirewallConfiguration.self, from: RootFiles.read(FirewallPaths.configuration))
        guard value.isValid else { throw FirewallError.invalidConfiguration }
        return value
    }
    func generation() throws -> String? {
        guard RootFiles.exists(FirewallPaths.armed) else { return nil }
        let value = String(decoding: try RootFiles.read(FirewallPaths.armed), as: UTF8.self)
        guard UUID(uuidString: value) != nil else { throw FirewallError.unsafeFile }
        return value
    }
    func writeStatus(_ state: FirewallStatus.State, _ detail: String, interface: String? = nil) throws {
        try RootFiles.write(JSONEncoder().encode(FirewallStatus(state: state, detail: detail, interface: interface)),
                            to: FirewallPaths.status, mode: 0o644)
    }

    /// Install while disabled. Never run a build system as root.
    func install(configurationPath: String, executablePath: String) throws {
        try RootFiles.requireRoot()
        let data = try RootFiles.read(configurationPath, rootOwned: false)
        let configuration = try JSONDecoder().decode(FirewallConfiguration.self, from: data)
        guard configuration.isValid else { throw FirewallError.invalidConfiguration }
        let executable = try RootFiles.read(executablePath, rootOwned: false, limit: 64 * 1024 * 1024)
        try RootFiles.checkDirectory(FirewallPaths.directory, create: true)
        try RootFiles.checkDirectory("/Library/PrivilegedHelperTools", create: true)
        try RootFiles.checkDirectory("/Library/LaunchDaemons")
        try RootFiles.locked {
            guard try generation() == nil, !RootFiles.exists(FirewallPaths.plist) else { throw FirewallError.unsafeFile }
            try RootFiles.write(executable, to: FirewallPaths.binary, mode: 0o755)
            try RootFiles.write(JSONEncoder().encode(configuration), to: FirewallPaths.configuration)
            let plist: [String: Any] = [
                "Label": FirewallPaths.label,
                "ProgramArguments": [FirewallPaths.binary, "run"],
                "RunAtLoad": true, "KeepAlive": true, "UserName": "root",
                "ThrottleInterval": 2, "ProcessType": "Background",
                "WorkingDirectory": "/", "Umask": 0o077
            ]
            try RootFiles.write(PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
                                to: FirewallPaths.plist, mode: 0o644)
            try writeStatus(.disabled, "Служба установлена. Сетевой kill switch выключен.")
        }
        _ = try pf.command("/bin/launchctl", ["bootstrap", "system", FirewallPaths.plist])
    }

    func enable() throws {
        try RootFiles.locked {
            let configuration = try configuration()
            guard try generation() == nil else { throw FirewallError.unsafeFile }
            let original = String(decoding: try RootFiles.read(FirewallPaths.main), as: UTF8.self)
            let updated = try FirewallRules.installing(in: original)
            try pf.verifyMain(armed: false)
            try pf.verifyNoTranslations()
            guard !RootFiles.exists(FirewallPaths.backup), !RootFiles.exists(FirewallPaths.anchor) else { throw FirewallError.unsafeFile }
            // Durable recovery information precedes every network-side effect.
            try RootFiles.write(Data(original.utf8), to: FirewallPaths.backup)
            try RootFiles.write(Data(UUID().uuidString.utf8), to: FirewallPaths.armed)
            try RootFiles.write(Data(FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false).utf8),
                                to: FirewallPaths.anchor, mode: 0o600)
            try RootFiles.write(Data(updated.utf8), to: FirewallPaths.main, mode: 0o644)
            try pf.activateMain(ensureEnabled: ensureReference)
            try writeStatus(.blocked, "Прямой выход закрыт. Ожидание проверенного VPN; соединения всего Mac сброшены.")
        }
    }

    /// Also resumes an interrupted enable after a crash. Never restores open access on error.
    func recoverArmed() throws {
        let configuration = try configuration()
        let original = String(decoding: try RootFiles.read(FirewallPaths.backup), as: UTF8.self)
        let expected = try FirewallRules.installing(in: original)
        let current = String(decoding: try RootFiles.read(FirewallPaths.main), as: UTF8.self)
        guard current == original || current == expected else { throw FirewallError.incompatiblePF }
        try RootFiles.write(Data(FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false).utf8),
                            to: FirewallPaths.anchor)
        try RootFiles.write(Data(expected.utf8), to: FirewallPaths.main, mode: 0o644)
        try pf.validate(FirewallPaths.main)
        // On boot the main ruleset may be empty. After daemon restart never
        // overwrite foreign rules inserted since enable: report broken instead.
        let existing = try pf.mainFilterRules()
        if existing.isEmpty || existing == ["anchor \"com.apple/*\" all"] {
            try pf.loadMain()
        } else {
            try pf.verifyMain(armed: true)
            try pf.applyAnchor()
        }
        try ensureReference()
        try pf.flushStates()
    }

    /// Explicit administrative recovery. Restore only our known edit; never
    /// replace another administrator's intervening configuration silently.
    func disable() throws {
        try RootFiles.locked {
            guard RootFiles.exists(FirewallPaths.backup) else {
                guard try generation() == nil else { throw FirewallError.unsafeFile }
                try writeStatus(.disabled, "Сетевой kill switch выключен.")
                return
            }
            let original = String(decoding: try RootFiles.read(FirewallPaths.backup), as: UTF8.self)
            let expected = try FirewallRules.installing(in: original)
            let current = String(decoding: try RootFiles.read(FirewallPaths.main), as: UTF8.self)
            guard current == expected || current == original else { throw FirewallError.incompatiblePF }
            // Check live rules before removing the only packet guard.
            let live = try pf.mainFilterRules()
            guard live.isEmpty || live == ["anchor \"com.apple/*\" all"] || live == ["anchor \"app.russian-armor\" quick all", "anchor \"com.apple/*\" all"] else {
                throw FirewallError.incompatiblePF
            }
            try RootFiles.write(Data(original.utf8), to: FirewallPaths.main, mode: 0o644)
            try pf.validate(FirewallPaths.main)
            try pf.loadMain()
            try RootFiles.remove(FirewallPaths.armed)
            try releaseReference()
            try RootFiles.remove(FirewallPaths.anchor)
            try RootFiles.remove(FirewallPaths.backup)
            try writeStatus(.disabled, "Сетевой kill switch явно выключен. Исходный pf.conf восстановлен; PF глобально не отключался.")
        }
    }
}

actor ProbeResultBox {
    private var value: Result<TunnelCheckResult, Error>?
    func set(_ value: Result<TunnelCheckResult, Error>) { self.value = value }
    func take() -> Result<TunnelCheckResult, Error>? { defer { value = nil }; return value }
}

/// The GUI is not a privileged IPC client. This service owns its own root-only
/// policy and probes, so GUI crashes/exit cannot disable the packet guard.
final class FirewallDaemon {
    private let installation = FirewallInstallation()
    private var generation: String?
    private var configuration: FirewallConfiguration?
    private var recovery = FirewallRecovery()
    private var probe: Task<Void, Never>?
    private var box = ProbeResultBox()
    private var nextProbe: TimeInterval = 0
    private var previousTunnel: VerifiedTunnel?
    private var appliedRules: String?
    private var appliedKernelRules: String?
    private var lastTick: TimeInterval?

    private func uptime() -> TimeInterval {
        var time = timespec()
        clock_gettime(CLOCK_MONOTONIC_RAW, &time)
        return Double(time.tv_sec) + Double(time.tv_nsec) / 1_000_000_000
    }
    private func reset() {
        recovery.reset(); probe?.cancel(); probe = nil; box = ProbeResultBox()
        previousTunnel = nil; nextProbe = 0; appliedRules = nil; appliedKernelRules = nil
    }
    private func model(_ tunnel: VerifiedTunnel) -> FirewallTunnel {
        .init(interface: tunnel.interface, addresses: tunnel.sourceAddresses,
              identity: "\(tunnel.ownerKey)|\(tunnel.owner.pid)|\(tunnel.owner.startSeconds)|\(tunnel.owner.startMicroseconds)|\(tunnel.interface)|\(tunnel.sourceAddresses.sorted())")
    }

    func run() async {
        while !Task.isCancelled {
            do { try await tick() }
            catch {
                reset()
                try? RootFiles.locked {
                    // Do not overwrite an explicit disable from a concurrent CLI.
                    guard try installation.generation() != nil else { return }
                    let blocked = (try? installation.configuration()).flatMap {
                        try? FirewallRules.render(configuration: $0, tunnel: nil, allowTraffic: false)
                    } ?? "pass quick on lo0 all no state\nblock drop quick all\n"
                    try RootFiles.write(Data(blocked.utf8), to: FirewallPaths.anchor)
                    try? installation.pf.applyAnchor()
                    try installation.writeStatus(.broken, "Ошибка службы или pf. Защита не подтверждена; правила не снимаются. Требуется проверка администратором.")
                }
                generation = nil
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
        // Deliberately no cleanup that opens network access on termination.
    }

    private func tick() async throws {
        let current = try RootFiles.locked { try installation.generation() }
        guard let current else {
            if generation != nil { reset(); generation = nil; configuration = nil }
            try RootFiles.locked {
                if try installation.generation() == nil {
                    try installation.writeStatus(.disabled, "Сетевой kill switch выключен.")
                }
            }
            return
        }
        if current != generation {
            reset()
            try RootFiles.locked {
                guard try installation.generation() == current else { return }
                try installation.recoverArmed()
                configuration = try installation.configuration()
                generation = current
            }
        }
        guard generation == current, let configuration else { return }
        let started = uptime()
        // Wake/scheduler stalls invalidate geographic evidence.
        if let lastTick, started - lastTick > 5 || started < lastTick { reset() }
        lastTick = started
        let ownerKey = configuration.vpnOwnerKey
        let tunnels = try await Task.detached(priority: .utility) { try TunnelOwnershipReader.read() }.value
        let now = uptime()
        let tunnel = try? TunnelOwnershipReader.select(tunnels, ownerKey: ownerKey)
        if tunnel != previousTunnel { reset(); previousTunnel = tunnel }
        if let result = await box.take() {
            probe = nil
            switch result {
            case .success(let result) where result.tunnel == tunnel:
                let countries: Set<String> = [result.first.countryCode, result.second.countryCode]
                recovery.observe(tunnel: model(result.tunnel), ip: result.first.ip, countries: countries,
                                 allowed: configuration.rules.evaluate(ip: result.first.ip, countries: countries).allowed, now: now)
            default: recovery.reset()
            }
            nextProbe = now + (tunnel.map { recovery.permits(model($0), now: now) } == true ? 10 : 2)
        }
        try RootFiles.locked {
            guard try installation.generation() == current else { return }
            try installation.pf.verifyMain(armed: true)
            try installation.pf.verifyNoTranslations()
            guard try installation.pf.isEnabled() else { throw FirewallError.commandFailed("PF disabled") }
            if let appliedKernelRules {
                let live = try installation.pf.command(PFDriver.pfctl, ["-a", FirewallRules.anchor, "-s", "rules"])
                guard live == appliedKernelRules else { throw FirewallError.incompatiblePF }
            }
            let allowed = tunnel.map { recovery.permits(model($0), now: now) } ?? false
            let rules = try FirewallRules.render(configuration: configuration, tunnel: tunnel.map(model), allowTraffic: allowed)
            if rules != appliedRules {
                // Disk always contains blocked rules, even while the live anchor
                // allows a tunnel. Reboot must not reload an old permission.
                let blocked = try FirewallRules.render(configuration: configuration, tunnel: nil, allowTraffic: false)
                let livePath = FirewallPaths.directory + "/live.pf"
                try RootFiles.write(Data(rules.utf8), to: livePath)
                try installation.pf.validate(livePath)
                _ = try installation.pf.command(PFDriver.pfctl, ["-a", FirewallRules.anchor, "-f", livePath])
                try RootFiles.write(Data(blocked.utf8), to: FirewallPaths.anchor)
                appliedRules = rules
                appliedKernelRules = try installation.pf.command(PFDriver.pfctl, ["-a", FirewallRules.anchor, "-s", "rules"])
            }
            try installation.writeStatus(allowed ? .protected : tunnel == nil ? .blocked : .recovering,
                                         allowed ? "Трафик всего Mac допускается только через проверенный туннель. Политика службы подтверждена."
                                         : "Прямой выход закрыт. Проверки восстановления: \(recovery.successes)/3. Исключения VPN и DHCP остаются.",
                                         interface: tunnel?.interface)
        }
        if let tunnel, probe == nil, now >= nextProbe {
            let box = self.box
            probe = Task.detached(priority: .utility) {
                do { await box.set(.success(try await TunnelEgressChecker.check(ownerKey: tunnel.ownerKey, probeAddresses: configuration.probeAddresses))) }
                catch { await box.set(.failure(error)) }
            }
        }
    }
}
