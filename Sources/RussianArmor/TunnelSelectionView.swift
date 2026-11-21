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
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 8) {
                Text(model.verifiedTunnel?.title ?? "Не подтверждён")
                    .font(.system(size: 13))
                if let preferred = model.preferences.preferredTunnelOwner {
                    Text("Выбран: \(preferred)").font(.system(size: 13)).textSelection(.enabled)
                    Button("Сбросить выбор владельца") { model.preferences.preferredTunnelOwner = nil }
                }
                Text("Если VPN-приложение не подтверждено, Claude остаётся на паузе.")
                    .font(.system(size: 13)).foregroundStyle(.secondary)
                DisclosureGroup("Hiddify, Clash и проверка туннеля") {
                    Text("Проверяется владелец туннеля и подпись процесса. При неоднозначности — пауза без перехода на Wi-Fi. Подпись не подтверждает надёжность поставщика VPN.")
                        .font(.caption).foregroundStyle(.secondary)
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
                    .font(.system(size: 13))
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
                if let message { Text(message).font(.system(size: 13)).foregroundStyle(.orange) }
            }.frame(maxWidth: .infinity, alignment: .leading)
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
        .font(.system(size: 13))
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
