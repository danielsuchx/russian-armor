import ArmorCore
import ArmorTunnel
import Darwin
import Foundation

@main
struct ArmorFirewallCommand {
    static func main() async {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard let action = arguments.first else { printHelp(); return }
            switch action {
            case "example":
                let value = FirewallConfiguration(physicalInterface: "en0", vpnOwnerKey: "TEAMID/vpn.bundle.identifier",
                    endpoints: [.init(address: "192.0.2.10", port: 51820, transport: "udp")],
                    probeAddresses: ["ipwho.is": "192.0.2.20", "ipinfo.io": "192.0.2.30"],
                    rules: AccessRules(allowedCountries: ["NL"], deniedCountries: ["RU"]))
                let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                print(String(decoding: try encoder.encode(value), as: UTF8.self))
            case "validate", "render":
                guard arguments.count == 2 else { throw FirewallError.invalidConfiguration }
                let value = try JSONDecoder().decode(FirewallConfiguration.self,
                    from: RootFiles.read(arguments[1], rootOwned: false))
                guard value.isValid else { throw FirewallError.invalidConfiguration }
                if action == "render" {
                    print(try FirewallRules.render(configuration: value, tunnel: nil, allowTraffic: false), terminator: "")
                } else { print("Configuration valid. No system changes made.") }
            case "tunnels":
                for tunnel in try TunnelOwnershipReader.read() {
                    print("\(tunnel.ownerKey)\t\(tunnel.interface)")
                }
            case "install":
                guard arguments.count == 2 else { throw FirewallError.invalidConfiguration }
                try FirewallInstallation().install(configurationPath: arguments[1], executablePath: Bundle.main.executablePath ?? CommandLine.arguments[0])
                print("Installed and started DISABLED. No firewall rules changed.")
            case "install-vpn":
                guard arguments.count == 3 else { throw FirewallError.invalidConfiguration }
                try FirewallInstallation().install(configurationPath: arguments[1], executablePath: Bundle.main.executablePath ?? CommandLine.arguments[0], vpnCorePath: arguments[2])
                print("Installed owned VPN service DISABLED.")
            case "replace-vpn":
                guard arguments.count == 3 else { throw FirewallError.invalidConfiguration }
                try FirewallInstallation().replaceVPN(configurationPath: arguments[1], executablePath: Bundle.main.executablePath ?? CommandLine.arguments[0], vpnCorePath: arguments[2])
                print("Replaced owned VPN service DISABLED.")
            case "preflight-vpn":
                try requireInstalled()
                guard arguments.count == 1 else { throw FirewallError.invalidConfiguration }
                try RootFiles.locked {
                    guard try FirewallInstallation().generation() == nil else { throw FirewallError.unsafeFile }
                    let configuration = try FirewallInstallation().configuration()
                    let session = OwnedVPNSession(configuration)
                    do {
                        try session.start(probeOnly: true)
                        guard let tunnel = session.tunnel else { throw FirewallError.commandFailed("VPN preflight") }
                        for (host, path, provider) in [("ipwho.is", "/", EgressProvider.ipWhoIS), ("ipinfo.io", "/json", .ipInfo)] {
                            let address = configuration.probeAddresses[host]!
                            let body = try systemCommand("/usr/bin/curl", ["--fail", "--silent", "--show-error", "--max-time", "4", "--noproxy", "*", "--interface", tunnel.interface,
                                "--resolve", "\(host):443:\(address)", "https://\(host)\(path)"])
                            let observation = try EgressObservation.decode(Data(body.utf8), provider: provider)
                            guard observation.ip == configuration.ownedVPN?.expectedExitIP,
                                  configuration.rules.evaluate(ip: observation.ip, countries: [observation.countryCode]).allowed else { throw FirewallError.commandFailed("VPN exit mismatch") }
                        }
                        try OwnedVPNSession.restore()
                        print("VPN preflight passed; exit matches the pinned VPS. Normal routes restored. PF was not enabled.")
                    } catch {
                        try OwnedVPNSession.restore()
                        throw error
                    }
                }
            case "start":
                try requireInstalled()
                guard arguments.count == 1 else { throw FirewallError.invalidConfiguration }
                _ = try systemCommand("/bin/launchctl", ["bootstrap", "system", FirewallPaths.plist])
                print("Service started. Persistent armed/disabled choice was not changed.")
            case "enable":
                try requireInstalled()
                guard arguments == ["enable", "--acknowledge-whole-mac-outage"] else { throw FirewallError.invalidConfiguration }
                do { try FirewallInstallation().enable() }
                catch {
                    try? RootFiles.locked { try FirewallInstallation().writeStatus(.broken, "Включение не завершено. Используйте status и явный disable; доступ автоматически не открывается.") }
                    throw error
                }
                print("Direct egress blocked. Existing connections flushed. VPN recovery is independent of the GUI.")
            case "disable":
                try requireInstalled()
                guard arguments.count == 1 else { throw FirewallError.invalidConfiguration }
                try FirewallInstallation().disable()
                print("Kill switch disabled explicitly. Original pf.conf restored; PF was not globally disabled.")
            case "run":
                try requireInstalled()
                guard arguments.count == 1 else { throw FirewallError.invalidConfiguration }
                // launchd owns daemon lifetime. Do not start concurrent manual daemons.
                guard getppid() == 1 else { throw FirewallError.unsafeFile }
                await FirewallDaemon().run()
            case "status":
                // Reading status grants no control over the privileged service.
                let data = try RootFiles.read(FirewallPaths.status, rootOwned: false)
                let status = try JSONDecoder().decode(FirewallStatus.self, from: data)
                print("\(status.state.rawValue)\(status.isFresh(at: Date()) ? "" : " (STALE: NOT VERIFIED)"): \(status.detail)")
            case "uninstall":
                try requireInstalled()
                try FirewallInstallation().disable()
                _ = try systemCommand("/bin/launchctl", ["bootout", "system/" + FirewallPaths.label])
                try RootFiles.locked {
                    for file in [FirewallPaths.configuration, FirewallPaths.status,
                                 FirewallPaths.directory + "/live.pf", FirewallPaths.plist, FirewallPaths.binary, FirewallPaths.vpnCore] {
                        if RootFiles.exists(file) { _ = try RootFiles.read(file, limit: 64 * 1024 * 1024); guard unlink(file) == 0 else { throw FirewallError.unsafeFile } }
                    }
                }
                print("Service removed after explicit disable. No global PF disable was performed.")
            case "help", "--help", "-h": printHelp()
            default: throw FirewallError.invalidConfiguration
            }
        } catch {
            fputs("ArmorFirewall: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
    private static func requireInstalled() throws {
        try RootFiles.requireRoot()
        guard Bundle.main.executablePath == FirewallPaths.binary else { throw FirewallError.unsafeFile }
        _ = try RootFiles.read(FirewallPaths.binary, limit: 64 * 1024 * 1024)
    }
    private static func printHelp() {
        print("""
        ArmorFirewall — EXPERIMENTAL whole-Mac PF kill switch (local VPN only)
        No command runs implicitly. Build as your normal user, never with sudo.
          example                   Print sample JSON; TEST-NET IPs MUST be replaced
          tunnels                   List signed local tunnel owners (read-only)
          validate CONFIG.json      Validate without root or network requests
          render CONFIG.json        Print blocked anchor; does not invoke pfctl
          install CONFIG.json       Explicit sudo install; starts DISABLED
          replace-vpn CONFIG.json    Replace installed owned-VPN helper while disabled
        Installed helper only, explicit sudo:
          start                     Retry launchd bootstrap after a failed install
          enable --acknowledge-whole-mac-outage
          disable                   Restore original pf.conf, even if GUI is closed
          uninstall                 Disable, stop service, remove installed files
          status                    Read status (no sudo needed)
        See docs/kill-switch.md before any installation. Not VM-validated yet.
        """)
    }
}
