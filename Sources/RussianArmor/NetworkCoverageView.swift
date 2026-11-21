import SwiftUI

struct NetworkCoverageView: View {
    @ObservedObject var engine: NetworkEngineStore
    @State private var confirmsRestart = false
    @State private var selectedApp: AppSelection?
    @State private var showNotInstalled = false
    private struct AppSelection: Identifiable {
        let value: EngineValue
        var id: String { value["id"].string }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Text("Статус по запросам через шлюз").foregroundStyle(.secondary)
                Spacer()
                Button("Проверить") { engine.perform("recheck_coverage") }
            }
            EngineSection(title: "") {
                ForEach(engine.coverage["apps"].array.filter { showNotInstalled || $0["status"].string != "not_installed" }, id: \.["id"].string) { app in
                    VStack(alignment: .leading, spacing: 8) {
                        SettingsDetailLink(title: app["name"].string, detail: status(app["status"].string)) { selectedApp = .init(value: app) }
                        if app["bypass_suspected"].bool {
                            Label("Трафик запущенного приложения не подтверждён", systemImage: "exclamationmark.triangle")
                                .font(.caption).foregroundStyle(.orange)
                        }
                        Divider()
                    }
                }
                Toggle("Показывать неустановленные", isOn: $showNotInstalled).font(.caption)
            }
            DisclosureGroup("Ручная настройка и браузеры") {
                EngineSection(title: "") {
                    LabeledContent("HTTP-прокси", value: engine.display(engine.gateway)).textSelection(.enabled)
                    if let pac = engine.coverage["pac_url"].optionalString {
                        LabeledContent("PAC", value: engine.display(pac)).textSelection(.enabled)
                        Button("Скопировать PAC") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(pac, forType: .string) }
                    }
                    Button("Обновить политики браузеров") { engine.perform("reapply_browser_policies_cmd") }
                    Button("Перезапустить браузеры с прокси…") { confirmsRestart = true }
                    Button("Настройки сети macOS") { engine.perform("open_os_network_settings_cmd") }
                }.padding(.top, 10)
            }
            Text("Настроенный прокси не подтверждает маршрут: нужен запрос приложения через шлюз.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .sheet(item: $selectedApp) { item in
            SettingsDetailSheet(title: item.value["name"].string) {
                EngineSection(title: status(item.value["status"].string)) {
                    Text(engine.display(item.value["detail"].string))
                    ForEach(item.value["manual_steps"].array.map(\.string), id: \.self) { step in Text(engine.display(instruction(step))) }
                    if item.id == "antigravity", item.value["installed"].bool {
                        Button("Перезапустить с защитой") { engine.perform("restart_app_with_gateway", args: ["appId": .string("antigravity")]) }
                    }
                    if item.value["ai_requests"].number > 0 { Text("Запросов через шлюз: \(Int(item.value["ai_requests"].number))").foregroundStyle(.secondary) }
                }
            }
        }
        .alert("Перезапустить браузеры?", isPresented: $confirmsRestart) {
            Button("Отмена", role: .cancel) {}
            Button("Перезапустить") { engine.perform("relaunch_browsers_with_pac_cmd") }
        } message: { Text("Открытые поддерживаемые браузеры будут мягко закрыты и открыты с PAC шлюза. Завершите работу с несохранёнными формами.") }
    }
    private func status(_ value: String) -> String {
        switch value {
        case "confirmed": return "Подтверждено трафиком"
        case "configured": return "Настроено · ждём первый запрос"
        case "off": return "Не настроено"
        case "not_installed": return "Не установлено"
        default: return "Неизвестно"
        }
    }
    private func instruction(_ step: String) -> String {
        switch step {
        case "enable_protection", "enable_system_proxy": return "Включите системный прокси в разделе «Сетевой шлюз»."
        case "set_http_proxy": return "Укажите HTTP-прокси \(engine.gateway) в настройках приложения."
        case "set_pac_url": return "Укажите PAC: \(engine.coverage["pac_url"].string)."
        case "set_env_proxy", "launch_with_env": return "Запустите с HTTPS_PROXY=http://\(engine.gateway) и HTTP_PROXY=http://\(engine.gateway)."
        case "restart_app": return "Перезапустите приложение, чтобы оно подхватило настройки."
        case "reopen_terminal": return "Откройте новое окно терминала."
        case "jetbrains_proxy_settings": return "Откройте HTTP Proxy в настройках JetBrains и настройте прокси вручную. Формат автоматической настройки пока не подтверждён."
        default: return "Проверьте настройки прокси приложения."
        }
    }
}
