import AppKit
import ArmorCore
import Combine
import Foundation
import UniformTypeIdentifiers
import SwiftUI

@MainActor
final class PacketGuardStore: ObservableObject {
    @Published private(set) var status: FirewallStatus?
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    @Published private(set) var requested: Bool
    private let defaults: UserDefaults
    private var polling: Task<Void, Never>?
    private let reader: () -> FirewallStatus?
    init(defaults: UserDefaults = .standard, monitoring: Bool = true, reader: @escaping () -> FirewallStatus? = FirewallStatusReader.read) {
        self.defaults = defaults; self.reader = reader
        requested = defaults.bool(forKey: "armor.packet-guard.required")
        status = reader()
        if status.map({ $0.state != .disabled }) == true {
            requested = true; defaults.set(true, forKey: "armor.packet-guard.required")
        }
        if monitoring {
            polling = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self else { return }
                    self.refresh()
                    do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
                }
            }
        }
    }
    deinit { polling?.cancel() }
    var required: Bool { requested || status.map { $0.state != .disabled } == true }
    var verified: Bool { status?.isFresh(at: Date()) == true && status?.state == .protected && status?.policy == "owned-vpn" }
    var permitsClaude: Bool { !required || verified }
    var installed: Bool { FileManager.default.fileExists(atPath: FirewallPathsForUI.binary) }
    var title: String {
        guard let status, status.isFresh(at: Date()) else { return required ? "Блокировка не подтверждена" : "Строгий режим не включён" }
        switch status.state {
        case .protected: return "Прямой выход заблокирован"
        case .blocked: return "Сеть закрыта"
        case .recovering: return "Проверяем защищённый туннель"
        case .broken: return "Требуется восстановление"
        case .disabled: return "Строгий режим выключен"
        }
    }
    func refresh() {
        let nextStatus = reader()
        if status != nextStatus { status = nextStatus }
        if !requested, status.map({ $0.state != .disabled }) == true {
            requested = true; defaults.set(true, forKey: "armor.packet-guard.required")
        }
    }
    func importConfiguration() {
        chooseConfiguration { [weak self] url, helper, core in
            self?.run([helper, "install-vpn", url.path, core], requireProtection: false)
        }
    }
    func replaceConfiguration() {
        guard installed, !required else { return }
        chooseConfiguration { [weak self] url, helper, core in
            self?.run([helper, "replace-vpn", url.path, core], requireProtection: false)
        }
    }
    private func chooseConfiguration(_ action: (URL, String, String) -> Void) {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        panel.message = "Выберите конфигурацию строгого VPN. Файл содержит закрытый ключ и не входит в диагностические отчёты."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 65536 else { throw FirewallError.invalidConfiguration }
            let value = try JSONDecoder().decode(FirewallConfiguration.self, from: Data(contentsOf: url))
            guard value.isValid, value.ownedVPN != nil else { throw FirewallError.invalidConfiguration }
            let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/ArmorFirewall").path
            let core = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/ArmorWireGuard").path
            action(url, helper, core)
        } catch { self.error = "Не удалось прочитать конфигурацию VPN. Проверьте формат файла." }
    }
    func enable() { run([FirewallPathsForUI.binary, "enable", "--acknowledge-whole-mac-outage"], requireProtection: true) }
    func disable() { run([FirewallPathsForUI.binary, "disable"], requireProtection: false, disables: true) }
    private func run(_ arguments: [String], requireProtection: Bool, disables: Bool = false) {
        guard !busy else { return }
        if requireProtection {
            requested = true; defaults.set(true, forKey: "armor.packet-guard.required")
        }
        busy = true; error = nil
        // The product asks macOS to authorize its fixed helper command. No admin password is stored.
        let command = arguments.map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }.joined(separator: " ")
        let appleLiteral = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                    process.arguments = ["-e", "do shell script \"\(appleLiteral)\" with administrator privileges"]
                    process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
                    try process.run(); process.waitUntilExit()
                    guard process.terminationStatus == 0 else { throw FirewallError.commandFailed("authorization") }
                }.value
                if disables { requested = false; defaults.set(false, forKey: "armor.packet-guard.required") }
            } catch { self.error = "Операция не завершена или разрешение отменено. Проверьте состояние защиты." }
            refresh(); busy = false
        }
    }
}
private enum FirewallPathsForUI {
    static let binary = "/Library/PrivilegedHelperTools/app.russian-armor.firewall"
}

struct PacketGuardView: View {
    @ObservedObject var guardStore: PacketGuardStore
    @State private var confirmEnable = false
    @State private var confirmDisable = false
    var body: some View {
        SettingsCard(title: "Строгая сетевая защита · весь Mac") {
            Label(guardStore.title, systemImage: guardStore.verified ? "lock.shield" : "shield.slash")
                .font(.system(size: 15, weight: .semibold))
            if let status = guardStore.status, status.isFresh(at: Date()) {
                Text(status.detail).font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Внешний IPv4 — через отдельный VPN. Прямой выход и IPv6 блокируются независимо от окна приложения.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if guardStore.installed {
                HStack {
                    Button("Включить строгий режим…") { confirmEnable = true }.disabled(guardStore.required)
                    if guardStore.required { Button("Отключить блокировку…") { confirmDisable = true } }
                    if !guardStore.required { Button("Обновить VPN-службу…") { guardStore.replaceConfiguration() } }
                    if guardStore.busy { ProgressView().controlSize(.small) }
                }
            } else {
                Button("Импортировать конфигурацию VPN…") { guardStore.importConfiguration() }
            }
            if let error = guardStore.error { Text(error).font(.caption).foregroundStyle(.orange) }
        }
        .disabled(guardStore.busy)
        .alert("Включить защиту для всего Mac?", isPresented: $confirmEnable) {
            Button("Отмена", role: .cancel) {}
            Button("Включить") { guardStore.enable() }
        } message: { Text("Текущие соединения будут разорваны. Интернет появится только после проверки VPN. При обрыве VPN сеть останется заблокирована. Потребуется разрешение администратора.") }
        .alert("Разрешить обычный выход в интернет?", isPresented: $confirmDisable) {
            Button("Отмена", role: .cancel) {}
            Button("Отключить", role: .destructive) { guardStore.disable() }
        } message: { Text("Настройки DNS и маршрутов будут восстановлены. После этого программы смогут подключаться без строгого VPN.") }
    }
}
