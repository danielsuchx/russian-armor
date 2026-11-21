import ArmorCore
import SwiftUI

struct ClaudeRoutesView: View {
    @Environment(\.networkAddressesHidden) private var hideIP
    @ObservedObject var monitor: ClaudeRouteMonitor
    let vpnLocation: VPNLocation
    @State private var showsDetails = false

    var body: some View {
        GroupBox("Соединения Claude Desktop и Code") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(monitor.state.title).font(.headline)
                    Spacer()
                    Button("Обновить", action: monitor.refresh)
                        .disabled(monitor.state == .sleeping || monitor.state == .off)
                }
                if let snapshot = monitor.state.snapshot {
                    if let reason = snapshot.pauseReason(vpnLocation: vpnLocation) {
                        Label(reason, systemImage: "exclamationmark.triangle")
                            .font(AppTypography.description).foregroundStyle(.orange)
                    }
                }
                Text(vpnLocation == .thisMac
                     ? "Маршрут вне VPN или ошибка проверки — пауза Claude."
                     : "Выход за роутером не виден; страна проверяется отдельно.")
                    .font(AppTypography.description).foregroundStyle(.secondary)

                DisclosureGroup("Подробности", isExpanded: $showsDetails) {
                    VStack(alignment: .leading, spacing: 10) {
                        if let snapshot = monitor.state.snapshot {
                            Text("Обновлено: \(snapshot.capturedAt.formatted(date: .omitted, time: .standard)) · автоматически раз в секунду")
                                .font(AppTypography.description).foregroundStyle(.secondary)
                            ForEach(snapshot.routes.prefix(8)) { route in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("\(route.connection.process.name) · PID \(route.connection.process.id.pid) · \(route.connection.transport.rawValue)")
                                        .font(AppTypography.description.weight(.semibold))
                                    Text(hideIP ? EnginePrivacy.display("\(route.connection.local.title) → \(route.connection.remote.title)") : "\(route.connection.local.title) → \(route.connection.remote.title)")
                                        .font(AppTypography.description.monospaced()).textSelection(.enabled)
                                    Text(route.title).font(AppTypography.description).foregroundStyle(.secondary)
                                    Text("Интерфейс адреса источника: \(route.sourceInterfaces.isEmpty ? "не найден" : route.sourceInterfaces.joined(separator: ", ")). Маршрут ОС к узлу: \(route.routeInterface ?? "не найден").")
                                        .font(AppTypography.description).foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            if snapshot.routes.count > 8 {
                                Text("Ещё соединений: \(snapshot.routes.count - 8). Правило проверяет весь полученный снимок, не только строки выше.")
                                    .font(AppTypography.description).foregroundStyle(.secondary)
                            }
                        }
                        Text("Показаны соединения Claude Desktop и Code и маршруты macOS. Это не подтверждение безопасного выхода: адрес после роутера, прокси и per-app VPN не виден. Отсутствие соединений не гарантирует безопасность будущих запросов.")
                            .font(AppTypography.description).foregroundStyle(.secondary)
                        Text("Локальное соединение само по себе не вызывает паузу. В режиме VPN на Mac неизвестный маршрут или неполный снимок ставит Claude на паузу; имя туннеля не подтверждает владельца и страну.")
                            .font(AppTypography.description).foregroundStyle(.secondary)
                        Text("Данные хранятся в памяти. Содержимое запросов не читается.")
                            .font(AppTypography.description).foregroundStyle(.secondary)
                    }
                    .padding(.top, 6)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
        }
    }
}
