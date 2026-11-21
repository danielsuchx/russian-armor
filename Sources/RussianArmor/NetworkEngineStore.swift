import AppKit
import Combine
import Foundation

@MainActor
final class NetworkEngineStore: ObservableObject {
    typealias Transport = @Sendable (String, [String: EngineValue]) async throws -> EngineValue
    static let providers = [("anthropic", "Claude"), ("openai", "ChatGPT"), ("gemini", "Gemini")]
    @Published private(set) var connected = false
    @Published private(set) var starting = false
    @Published private(set) var error: String?
    @Published private(set) var notice: String?
    @Published private(set) var state: EngineValue = .null
    @Published private(set) var routes: EngineValue = .null
    @Published private(set) var coverage: EngineValue = .null
    @Published private(set) var profiles: EngineValue = .null
    @Published private(set) var stats: EngineValue = .null
    @Published private(set) var pause: EngineValue = .null
    @Published private(set) var cli: EngineValue = .null
    @Published private(set) var reports: [String: EngineValue] = [:]
    @Published private(set) var reportDates: [String: Date] = [:]
    @Published private(set) var pendingAlert: EngineValue = .null
    @Published var importedRoute: String?
    @Published private(set) var sysproxy = false
    @Published private(set) var cliEnabled = false
    @Published private(set) var busy = Set<String>()
    @Published private(set) var hideIP: Bool
    private var transport: Transport?
    private var process: Process?
    private var polling: Task<Void, Never>?
    private let defaults: UserDefaults
    private let fixture: Bool
    private var refreshInProgress = false
    private var lastHeartbeat: Date?

    init(defaults: UserDefaults = .standard, automaticallyStart: Bool = false, transport: Transport? = nil) {
        self.defaults = defaults
        hideIP = defaults.bool(forKey: "armor.privacy.hideIP")
        self.transport = transport
        fixture = transport != nil
        connected = transport != nil
        if connected { lastHeartbeat = Date() }
        if automaticallyStart && defaults.bool(forKey: "armor.network.enabled") {
            Task { await start() }
        }
    }
    deinit { polling?.cancel() }

    var routeItems: [EngineValue] { routes["routes"].array }
    var profileItems: [EngineValue] { profiles["profiles"].array }
    var gateway: String { coverage["gateway_addr"].optionalString ?? "Не получен" }
    var requiresHealthyGateway: Bool {
        defaults.bool(forKey: "armor.network.enabled") &&
            (defaults.bool(forKey: "armor.network.sysproxy") || defaults.bool(forKey: "armor.network.cli"))
    }
    var isHealthy: Bool {
        guard connected, let lastHeartbeat else { return false }
        let age = Date().timeIntervalSince(lastHeartbeat)
        return age >= 0 && age < 15
    }
    func display(_ text: String) -> String { hideIP ? EnginePrivacy.display(text) : text }

    func setHideIP(_ enabled: Bool) {
        hideIP = enabled
        defaults.set(enabled, forKey: "armor.privacy.hideIP")
        if connected { perform("set_hide_ip_mode", args: ["enabled": .bool(enabled)]) }
    }

    func call(_ command: String, _ args: [String: EngineValue] = [:]) async throws -> EngineValue {
        guard let transport else { throw NetworkEngineError.unavailable }
        return try await transport(command, args)
    }

    func start() async {
        guard !starting, !connected else { return }
        starting = true; error = nil
        defer { starting = false }
        do {
            let directory = try NetworkEngineClient.sessionDirectory()
            let client = try NetworkEngineClient.makeSession(in: directory)
            let existing = try? await client.call("native_ping")
            if existing?["protocol"].number != 1 {
                let executable = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/ArmorNetworkEngine.app/Contents/MacOS/ArmorNetworkEngine")
                guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw NetworkEngineError.missingHelper }
                let child = Process()
                child.executableURL = executable
                child.arguments = ["--native-bridge", client.socket, "--minimized"]
                child.standardOutput = FileHandle.nullDevice
                child.standardError = FileHandle.nullDevice
                try child.run()
                process = child
                var ready = false
                for _ in 0..<150 {
                    if !child.isRunning { break }
                    if let ping = try? await client.call("native_ping"), ping["protocol"].number == 1 { ready = true; break }
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                guard ready else { throw NetworkEngineError.unavailable }
            }
            transport = { command, args in try await client.call(command, args) }
            var recovered = false
            for _ in 0..<600 {
                let startup = try await client.call("get_startup_state")
                if startup["phase"].string == "ready" { recovered = true; break }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
            guard recovered else { throw NetworkEngineError.unavailable }
            _ = try await call("set_hide_ip_mode", ["enabled": .bool(hideIP)])
            if defaults.bool(forKey: "armor.network.sysproxy") {
                let applied = try await call("toggle_sysproxy", ["enable": .bool(true)])
                guard applied.bool else { throw NetworkEngineError.unavailable }
            }
            if defaults.bool(forKey: "armor.network.cli") {
                let applied = try await call("enable_cli_protection")
                guard applied["enabled"].bool else { throw NetworkEngineError.rejected(applied["error"]) }
            }
            // Published readiness must not precede recovery or reapplication
            // of the proxy configuration the user already enabled.
            connected = true
            lastHeartbeat = Date()
            defaults.set(true, forKey: "armor.network.enabled")
            await refresh()
            startPolling()
        } catch {
            self.error = (error as? NetworkEngineError)?.errorDescription ?? "Не удалось запустить сетевой модуль."
        }
    }

    private func startPolling() {
        polling?.cancel()
        polling = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { return }
                guard let self, self.connected else { return }
                await self.refresh(includeDetails: false)
            }
        }
    }

    func refresh(includeDetails: Bool = true) async {
        guard connected, !refreshInProgress else { return }
        refreshInProgress = true
        defer { refreshInProgress = false }
        do {
            let nextState = try await call("get_state")
            if state != nextState { state = nextState }
            lastHeartbeat = Date()
            let nextStats = try await call("get_gateway_stats")
            if stats != nextStats { stats = nextStats }
            let nextPause = try await call("get_guard_pause_status_cmd")
            if pause != nextPause { pause = nextPause }
            let nextSysproxy = try await call("get_sysproxy_status").bool
            if sysproxy != nextSysproxy { sysproxy = nextSysproxy }
            let nextCLIEnabled = try await call("check_cli_protection_status").bool
            if cliEnabled != nextCLIEnabled { cliEnabled = nextCLIEnabled }
            let events = try await call("native_poll_events")
            for event in events.array { receiveEvent(event) }
            let nextAlert = try await call("take_pending_alert")
            if pendingAlert != nextAlert { pendingAlert = nextAlert }
            if includeDetails {
                let nextRoutes = try await call("list_routes")
                if routes != nextRoutes { routes = nextRoutes }
                let nextCoverage = try await call("get_coverage_snapshot")
                if coverage != nextCoverage { coverage = nextCoverage }
                let nextProfiles = try await call("list_claude_profiles_cmd")
                if profiles != nextProfiles { profiles = nextProfiles }
                let nextCLI = try await call("get_cli_settings")
                if cli != nextCLI { cli = nextCLI }
            }
        } catch {
            self.error = (error as? NetworkEngineError)?.errorDescription ?? "Не удалось обновить состояние сетевого модуля."
            // A missing helper cannot leave a previous green snapshot on screen.
            if case NetworkEngineError.unavailable = error {
                connected = false; reports = [:]; reportDates = [:]; coverage = .null
                sysproxy = false; cliEnabled = false
            }
        }
    }

    func perform(_ command: String, args: [String: EngineValue] = [:], success: String? = nil) {
        guard !busy.contains(command) else { return }
        busy.insert(command); error = nil; notice = nil
        Task {
            defer { busy.remove(command) }
            do {
                let result = try await call(command, args)
                if command == "enable_cli_protection", !result["enabled"].bool {
                    throw NetworkEngineError.rejected(result["error"])
                }
                if command == "toggle_sysproxy" || command == "toggle_sysproxy_privileged" {
                    defaults.set(result.bool, forKey: "armor.network.sysproxy")
                    if !result.bool { defaults.set(false, forKey: "armor.network.cli") }
                }
                if command == "enable_cli_protection" { defaults.set(result["enabled"].bool, forKey: "armor.network.cli") }
                if command == "disable_cli_protection" { defaults.set(false, forKey: "armor.network.cli") }
                if ["add_route", "remove_route", "set_route_enabled", "bind_provider_route", "set_default_route",
                    "switch_claude_profile_cmd", "bind_route_to_claude_profile", "set_split_tunnel_mode"].contains(command) {
                    reports = [:]; reportDates = [:]
                }
                notice = success
                await refresh()
            } catch {
                self.error = (error as? NetworkEngineError)?.errorDescription ?? "Действие не выполнено."
            }
        }
    }

    func audit(_ provider: String) {
        let key = "audit-" + provider
        guard !busy.contains(key) else { return }
        busy.insert(key); reports[provider] = nil; reportDates[provider] = nil; error = nil
        Task {
            defer { busy.remove(key) }
            do {
                reports[provider] = try await call("audit_connection", ["provider": .string(provider), "forceRefresh": .bool(true)])
                reportDates[provider] = Date()
                await refresh()
            } catch {
                self.error = (error as? NetworkEngineError)?.errorDescription ?? "Не удалось выполнить проверки."
            }
        }
    }

    func resolveAlert(_ action: String, scope: String? = nil) {
        let alert = pendingAlert
        guard !busy.contains("resolve_interception") else { return }
        busy.insert("resolve_interception"); error = nil
        Task {
            defer { busy.remove("resolve_interception") }
            do {
                let applied = try await call("resolve_interception", ["id": alert["id"], "provider": alert["provider"],
                                                            "action": .string(action), "scope": .optional(scope ?? alert["scope"].optionalString)])
                guard applied.bool else { throw NetworkEngineError.rejected(.string("Это окно больше не актуально. Обновите состояние сети.")) }
                if pendingAlert["id"] == alert["id"] { pendingAlert = .null }
                await refresh()
            } catch { self.error = (error as? NetworkEngineError)?.errorDescription ?? "Решение не применено. Допуск не подтверждён." }
        }
    }

    func receiveEvent(_ event: EngineValue) {
        switch event["name"].string {
        case "interceptor://risk-detected":
            pendingAlert = event["payload"]
            if !pendingAlert["is_simulation"].bool { reports = [:]; reportDates = [:] }
        case "interceptor://resolved": pendingAlert = .null
        case "interceptor://enriched":
            let update = event["payload"]
            guard update["id"] == pendingAlert["id"] else { return }
            pendingAlert = .object(pendingAlert.object.merging(update.object) { _, new in new })
        default: break
        }
    }

    func shutdown(preservePreference: Bool = true) async throws {
        polling?.cancel(); polling = nil
        guard transport != nil else { return }
        do { _ = try await call("native_shutdown") }
        catch {
            connected = false
            self.error = (error as? NetworkEngineError)?.errorDescription ?? "Не удалось завершить восстановление настроек. Повторите выход из приложения."
            throw error
        }
        connected = false; transport = nil; sysproxy = false; cliEnabled = false
        if !preservePreference { defaults.set(false, forKey: "armor.network.enabled") }
    }
}
