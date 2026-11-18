import ArmorTunnel
import ArmorCore
import SwiftUI
import ServiceManagement

struct TunnelSelectionView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tunnels: [VerifiedTunnel] = []
    @State private var reading = false
    @State private var message: String?
    @State private var lastCheckFailure: String?


    var body: some View {
        GroupBox("Владелец локального туннеля") {
            VStack(alignment: .leading, spacing: 8) {
                Text(model.verifiedTunnel?.title ?? "Не подтверждён")
                    .font(AppTypography.description)
                if let preferred = model.preferences.preferredTunnelOwner {
                    Text("Выбран: \(preferred)").font(AppTypography.description).textSelection(.enabled)
                    Button("Сбросить выбор владельца") { model.preferences.preferredTunnelOwner = nil }
                }
                Text("Проверочные запросы привязаны к выбранному туннелю. Если подтвердить его нельзя, Claude остаётся на паузе.")
                    .font(AppTypography.description).foregroundStyle(.secondary)
                DisclosureGroup("Как проверяется туннель") {
                    Text("Проверяем сокет utun и подпись процесса. Проверочные запросы требуют этот интерфейс, используют IPv4 и TLS. При неоднозначности или недоступном владельце — пауза, без перехода на Wi-Fi. Подпись подтверждает идентичность, не надёжность поставщика VPN.")
                        .font(AppTypography.description).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                DisclosureGroup("Hiddify и Clash Verge Rev · VPN/TUN") {
                    TunnelReaderControls(registration: model.tunnelReaderRegistration) {
                        tunnels = []
                        model.refreshExternalIP()
                    }
                }
                Button(reading ? "Ищем…" : "Найти владельцев туннелей") {
                    reading = true; message = nil
                    Task { @MainActor in
                        do {
                            tunnels = try await Task.detached(priority: .utility) { try TunnelOwnershipReader.read() }.value
                            message = tunnels.isEmpty ? "Владельцы туннелей не найдены. Для Hiddify и Clash проверьте режим VPN/TUN и службу чтения выше." : nil
                        } catch {
                            tunnels = []
                            message = (error as? TunnelCheckError)?.errorDescription ?? "Не удалось получить список владельцев."
                        }
                        reading = false
                    }
                }.disabled(reading)
                ForEach(tunnels, id: \.interface) { tunnel in
                    let selected = model.preferences.preferredTunnelOwner == tunnel.ownerKey
                    Button(selected ? "Проверить IP и страну · \(tunnel.title)" : "Использовать \(tunnel.title)") {
                        if !selected { model.preferences.preferredTunnelOwner = tunnel.ownerKey }
                        model.refreshExternalIP()
                    }
                    .disabled(model.isSleeping || (selected && model.externalCheck.isChecking))
                    .font(AppTypography.description)
                }
                if model.preferences.preferredTunnelOwner != nil {
                    switch model.externalCheck {
                    case .checking:
                        ProgressView("Проверяем IP и страну…").controlSize(.small)
                    case .observed(let observation):
                        Text("Страна выхода: \(observation.countryName) (\(observation.countryCode))")
                    default: EmptyView()
                    }
                    if let lastCheckFailure {
                        Text("Последняя ошибка: \(lastCheckFailure)")
                            .foregroundStyle(.orange).textSelection(.enabled)
                    }
                }
                if let message { Text(message).font(AppTypography.description).foregroundStyle(.orange) }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
        .onReceive(model.$externalCheck) { check in
            switch check {
            case .failed(let reason): lastCheckFailure = reason
            case .observed, .notChecked, .needsRecheck: lastCheckFailure = nil
            case .checking: break
            }
        }
    }
}

private struct TunnelReaderControls: View {
    @ObservedObject var registration: TunnelReaderRegistration
    let changed: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("В Hiddify выберите режим VPN, в Clash Verge Rev — TUN Mode. Если владелец туннеля недоступен, включите службу чтения, затем нажмите «Найти владельцев туннелей».")
            if registration.status == .requiresApproval {
                Button("Разрешить в настройках macOS") { SMAppService.openSystemSettingsLoginItems() }
            }
            let registered = registration.status == .enabled || registration.status == .requiresApproval
            Button(registered ? "Отключить службу чтения" : "Включить службу чтения") {
                configure(enable: !registered)
            }
            if registration.status == .enabled {
                Button("Переподключить службу") { configure(enable: true) }
            }
            if let message = registration.message { Text(message).foregroundStyle(.orange) }
        }
        .disabled(registration.busy)
        .font(AppTypography.description)
        .onAppear { registration.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            registration.refresh()
        }
    }

    private func configure(enable: Bool) {
        Task {
            await registration.configure(enable: enable)
            changed()
        }
    }
}
