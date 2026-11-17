import ArmorTunnel
import ArmorCore
import SwiftUI

struct TunnelSelectionView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tunnels: [VerifiedTunnel] = []
    @State private var reading = false
    @State private var message: String?

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
                    Text("Читаем владельца utun через сокеты процесса и проверяем его подпись. Проверочные запросы требуют этот интерфейс, используют IPv4 и TLS. При неоднозначности или недоступном владельце — пауза, без перехода на Wi-Fi. Подпись подтверждает идентичность, не надёжность поставщика VPN.")
                        .font(AppTypography.description).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Button(reading ? "Ищем…" : "Найти владельцев туннелей") {
                    reading = true; message = nil
                    Task { @MainActor in
                        do {
                            tunnels = try await Task.detached(priority: .utility) { try TunnelOwnershipReader.read() }.value
                            message = tunnels.isEmpty ? "Читаемых подписанных владельцев не найдено. Системный или root-процесс может быть недоступен обычному приложению." : nil
                        } catch { message = "Не удалось получить полный список владельцев." }
                        reading = false
                    }
                }.disabled(reading)
                ForEach(tunnels, id: \.interface) { tunnel in
                    Button("Использовать \(tunnel.title)") {
                        model.preferences.preferredTunnelOwner = tunnel.ownerKey
                    }
                    .font(AppTypography.description)
                }
                if let message { Text(message).font(AppTypography.description).foregroundStyle(.orange) }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
}
