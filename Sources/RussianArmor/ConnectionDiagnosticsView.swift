import ArmorCore
import SwiftUI

struct ConnectionDiagnosticsView: View {
    @Environment(\.networkAddressesHidden) private var hideIP
    @ObservedObject var monitor: ConnectionDiagnosticsMonitor
    @Binding var enabled: Bool
    let expectedIP: String?

    var body: some View {
        GroupBox("DNS и адрес на узлах сервисов") {
            VStack(alignment: .leading, spacing: 10) {
                Toggle("Проверять узлы Claude каждые 15 секунд", isOn: $enabled)
                    .accessibilityIdentifier("settings-service-probes")
                Text("Опциональные GET к claude.ai и api.anthropic.com, без аккаунта, cookies, ключей и содержимого чатов. Используется недокументированный /cdn-cgi/trace: узел может не поддерживать проверку. Это диагностика, не условие допуска.")
                    .font(.caption).foregroundStyle(.secondary)
                switch monitor.state {
                case .notChecked: Text("Диагностика ещё не выполнена.")
                case .checking: Label("Проверяем конфигурацию DNS и включённые узлы…", systemImage: "clock")
                case .sleeping: Text("Диагностика приостановлена на время сна.")
                case .stale: Label("Свежего результата нет. Диагностика не подтверждена.", systemImage: "exclamationmark.triangle")
                case .observed(let snapshot):
                    Text(snapshot.dnsServers.isEmpty
                         ? "Адреса DNS-серверов недоступны. Это не означает отсутствие DNS."
                         : "DNS в конфигурации macOS: \(hideIP ? EnginePrivacy.display(snapshot.dnsServers.joined(separator: ", ")) : snapshot.dnsServers.joined(separator: ", "))")
                        .textSelection(.enabled)
                    ForEach(ServiceProbe.allCases, id: \.self) { service in
                        if let result = snapshot.services[service] {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(service.title).font(.subheadline.weight(.semibold))
                                switch result {
                                case .observed(let address):
                                    Text(hideIP ? EnginePrivacy.display(address) : address).textSelection(.enabled)
                                    Text(Self.comparison(address, expectedIP: expectedIP))
                                        .font(.caption).foregroundStyle(.secondary)
                                case .unavailable(let message):
                                    Label(message, systemImage: "questionmark.circle")
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    Text("Проверено: \(snapshot.checkedAt.formatted(date: .omitted, time: .standard))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("Это запросы Russian Armor через обычный сетевой стек, не реальные запросы Claude. Совпадение адресов не доказывает маршрут программы; различие может быть связано с IPv4/IPv6 или раздельной маршрутизацией. Список DNS не определяет фактического рекурсивного резолвера и не проверяет DoH или DNS-утечки. Данные — только в памяти.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
            .padding(8)
        }
    }

    static func comparison(_ address: String, expectedIP: String?) -> String {
        guard let expectedIP else { return "Нет свежего подтверждённого выхода для сравнения." }
        if let range = IPRange(address), range.contains(expectedIP) {
            return "Адрес совпадает с проверенным выходом Russian Armor."
        }
        return "Адрес отличается от проверенного выхода. Это повод проверить маршруты, не доказательство утечки."
    }
}
