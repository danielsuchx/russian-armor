import AppKit
import ArmorCore
import ArmorFilterIPC
import Combine
import Foundation
import NetworkExtension
import Security
import SystemExtensions

@MainActor
final class ClaudeNetworkFilterStore: NSObject, ObservableObject, @preconcurrency OSSystemExtensionRequestDelegate {
    @Published private(set) var verified = false
    @Published private(set) var waitingForApproval = false
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    private let defaults: UserDefaults
    private var connection: NSXPCConnection?
    private var heartbeat: Task<Void, Never>?
    private var lastReply: TimeInterval = 0
    private var inFlight = false
    private var sentAt: TimeInterval = 0
    private var generation = UUID()
    var policy: () -> ClaudeNetworkPolicy = { .init(desktopAllowed: false, codeAllowed: false, processes: []) }
    var required: Bool { defaults.bool(forKey: "armor.claude-filter.required") }
    var permitsClaude: Bool { !required || verified }
    var bundled: Bool { FileManager.default.fileExists(atPath: extensionURL.path) }
    private var extensionURL: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(ClaudeFilterIdentity.bundle).systemextension")
    }
    init(defaults: UserDefaults = .standard, monitoring: Bool = true) {
        self.defaults = defaults
        super.init()
        if monitoring, bundled {
            heartbeat = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self else { return }
                    self.sendPolicy()
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                }
            }
            Task { self.activate() }
        }
    }
    deinit { heartbeat?.cancel(); connection?.invalidate() }
    private func sendPolicy() {
        if verified, ProcessInfo.processInfo.systemUptime - lastReply >= 3 { verified = false }
        if inFlight, ProcessInfo.processInfo.systemUptime - sentAt >= 3 { invalidate() }
        guard bundled, !inFlight, let team = Self.teamIdentifier() else { return }
        if connection == nil {
            let client = NSXPCConnection(machServiceName: ClaudeFilterIdentity.service(team: team), options: .privileged)
            client.setCodeSigningRequirement("anchor apple generic and identifier \"\(ClaudeFilterIdentity.bundle)\" and certificate leaf[subject.OU] = \"\(team)\"")
            client.remoteObjectInterface = NSXPCInterface(with: ClaudeFilterProtocol.self)
            client.invalidationHandler = { [weak self] in Task { @MainActor in self?.invalidate() } }
            client.interruptionHandler = { [weak self] in Task { @MainActor in self?.invalidate() } }
            client.resume(); connection = client
        }
        guard let data = try? JSONEncoder().encode(policy()),
              let remote = connection?.remoteObjectProxyWithErrorHandler({ [weak self] _ in
                  Task { @MainActor in self?.invalidate() }
              }) as? ClaudeFilterProtocol else { return }
        inFlight = true
        sentAt = ProcessInfo.processInfo.systemUptime
        let generation = self.generation
        remote.updatePolicy(data) { [weak self] active in
            Task { @MainActor in
                guard let self, self.generation == generation else { return }
                self.inFlight = false
                if self.verified != active { self.verified = active }
                if active { self.lastReply = ProcessInfo.processInfo.systemUptime; self.waitingForApproval = false }
            }
        }
    }
    private func invalidate() {
        generation = UUID()
        connection?.invalidationHandler = nil; connection?.interruptionHandler = nil
        connection?.invalidate(); connection = nil; inFlight = false
        if verified { verified = false }
    }
    func activate() {
        guard bundled, !busy else {
            error = "В этой сборке нет подписанного сетевого фильтра. Нужны профиль Network Extension и действующий вход в Xcode → Settings → Accounts."
            return
        }
        busy = true; error = nil
        defaults.set(true, forKey: "armor.claude-filter.required")
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: ClaudeFilterIdentity.bundle, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { waitingForApproval = true; busy = false }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        busy = false; verified = false
        self.error = "macOS не включила фильтр Claude: \(error.localizedDescription)"
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        busy = false
        guard result == .completed else { error = "Для запуска фильтра Claude macOS требует перезагрузку."; return }
        Task {
            do {
                let manager = NEFilterManager.shared()
                try await manager.loadFromPreferences()
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true; config.filterPackets = false
                config.filterDataProviderBundleIdentifier = ClaudeFilterIdentity.bundle
                manager.providerConfiguration = config
                manager.localizedDescription = "Russian Armor · только Claude"
                manager.isEnabled = true
                try await manager.saveToPreferences()
                sendPolicy()
            } catch { self.error = "Не удалось разрешить фильтрацию Claude в macOS." }
        }
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    private static func teamIdentifier() -> String? {
        var code: SecCode?; var staticCode: SecStaticCode?; var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
