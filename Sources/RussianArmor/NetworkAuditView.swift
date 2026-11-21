import SwiftUI

struct NetworkAuditView: View {
    @ObservedObject var engine: NetworkEngineStore
    @State private var provider = "anthropic"
    private static let names = ["Страна выхода", "Закреплённый IP", "Смена страны и ASN", "Спам-базы",
                                "Тип адреса и ASN", "IPv6", "DNS-резолвер", "Часовой пояс", "Геолокация ОС",
                                "Reverse DNS", "Страна DNS", "Окружение CLI/IDE", "UDP / STUN", "Выход к сервису"]
    @State private var selectedCheck: CheckSelection?
    @State private var showsInfo = false
    private struct CheckSelection: Identifiable {
        let id: Int
        let value: EngineValue
        var title: String { id < NetworkAuditView.names.count ? NetworkAuditView.names[id] : "Проверка" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 16) {
                Picker("Сервис", selection: $provider) {
                    ForEach(NetworkEngineStore.providers, id: \.0) { id, name in Text(name).tag(id) }
                }.pickerStyle(.segmented).labelsHidden()
                Button(engine.busy.contains("audit-" + provider) ? "Проверяем…" : "Проверить") { engine.audit(provider) }
                    .buttonStyle(.borderedProminent).disabled(engine.busy.contains("audit-" + provider))
            }
            if let report = engine.reports[provider] {
                EngineSection(title: "Результат") {
                    HStack {
                        Text("\(report["telemetry"]["country_code"].string) · \(engine.display(report["telemetry"]["ip"].string))")
                            .font(.system(size: 15, weight: .semibold)).textSelection(.enabled)
                        Spacer()
                        Text(report["incomplete"].bool ? "Частично" : "Завершено").foregroundStyle(.secondary)
                    }
                    if report["incomplete"].bool {
                        Text("Не удалось выполнить проверок: \(Int(report["unknown_count"].number))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        if let date = engine.reportDates[provider] {
                            Text(context.date.timeIntervalSince(date) >= 30 ? "Результат устарел — повторите проверку" : "Проверено в \(date.formatted(date: .omitted, time: .standard))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                EngineSection(title: "Проверки") {
                    ForEach(Array(report["checks"].array.enumerated()), id: \.offset) { index, check in
                        if index > 0 { Divider() }
                        Button { selectedCheck = .init(id: index, value: check) } label: {
                            HStack(spacing: 10) {
                                Image(systemName: symbol(check)).foregroundStyle(color(check)).frame(width: 18)
                                Text(index < Self.names.count ? Self.names[index] : "Проверка").foregroundStyle(.primary)
                                Spacer(minLength: 4)
                                Text(status(check)).font(.caption).foregroundStyle(color(check))
                                Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(.tertiary)
                            }.contentShape(Rectangle())
                        }.buttonStyle(.plain)
                    }
                }
            } else if !engine.busy.contains("audit-" + provider) {
                EngineSection(title: "") {
                    Label("Результатов пока нет", systemImage: "checklist").font(.headline)
                    Text("Запустите проверку выбранного сервиса.").foregroundStyle(.secondary)
                }
            }
            DisclosureGroup("Закрепление IP и блокировка") {
                VStack(alignment: .leading, spacing: 12) {
                    SettingsToggle(title: "Строго проверять закреплённый IP", isOn: Binding(get: { engine.state["strict_pinning_enabled"].bool }, set: {
                        engine.perform("toggle_strict_pinning", args: ["enabled": .bool($0)])
                    }))
                    if let report = engine.reports[provider] {
                        HStack {
                            Button("Закрепить IP") { engine.perform("pin_current_ip", args: ["ip": report["telemetry"]["ip"], "provider": .string(provider)]) }
                            Button("Снять закрепление") { engine.perform("unpin_ip", args: ["provider": .string(provider)]) }
                        }
                        Button("Перепроверить и снять блокировку") { engine.perform("verify_and_unblock_provider", args: ["provider": .string(provider)]) }
                    }
                }.padding(.top, 10)
            }
            HStack {
                Text("Внешние сервисы видят IP проверочных запросов.").font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 4)
                Button("О проверках…") { showsInfo = true }.buttonStyle(.link).font(.caption)
            }
        }
        .sheet(item: $selectedCheck) { item in
            SettingsDetailSheet(title: item.title) {
                EngineSection(title: status(item.value)) {
                    Text(engine.display(item.value["message"].string))
                    Text("Код: \(item.value["code"].string)").font(.caption).foregroundStyle(.secondary)
                    if let source = item.value["measured_via"].optionalString { Text(engine.display(source)).foregroundStyle(.secondary) }
                    ForEach(Array(item.value["detail"]["sources"].array.enumerated()), id: \.offset) { _, source in
                        Text(engine.display("\(source["source"].string): \(source["state"].string) · \(source["operator"].string) · \(source["country"].string) \(source["addr"].string)"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .sheet(isPresented: $showsInfo) {
            SettingsDetailSheet(title: "О сетевых проверках", height: 280) {
                Text("14 проверок оценивают выход к сервису, IP, DNS, IPv6, STUN и окружение. Внешние источники видят адрес соответствующего запроса.")
                Text("Недоступный источник означает неизвестный результат. Проверки не гарантируют отсутствие утечек или ограничений аккаунта.")
            }
        }
    }
    private func status(_ check: EngineValue) -> String {
        if check["reason"].string == "not_applicable" { return "Не применимо" }
        switch check["status"].string {
        case "ok": return "Пройдено"
        case "warning": return "Требует внимания"
        case "critical": return "Ограничение"
        default: return "Не удалось проверить"
        }
    }
    private func color(_ check: EngineValue) -> Color {
        check["status"].string == "critical" ? .red : check["status"].string == "warning" ? .orange : .secondary
    }
    private func symbol(_ check: EngineValue) -> String {
        check["status"].string == "ok" ? "checkmark.circle" : check["status"].string == "unknown" ? "questionmark.circle" : "exclamationmark.triangle"
    }
}
