import AppKit
import SwiftUI

struct NetworkGuidesView: View {
    @ObservedObject var engine: NetworkEngineStore
    @State private var bin = ""
    @State private var result: EngineValue = .null
    @State private var checking = false
    @State private var failed = false
    @State private var street = ""
    @State private var city = ""
    @State private var region = ""
    @State private var postalCode = ""
    @State private var country = ""
    @State private var topic: GuideTopic?
    private enum GuideTopic: String, CaseIterable, Identifiable {
        case connection = "Свой сервер и VPN", apps = "Подключение приложений", privacy = "Приватность macOS"
        case bin = "Проверка BIN карты", project = "О проекте и источниках", address = "Платёжный адрес"
        var id: String { rawValue }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            EngineSection(title: "Подключение") {
                SettingsDetailLink(title: "Свой сервер и VPN") { topic = .connection }
                Divider()
                SettingsDetailLink(title: "Подключение приложений") { topic = .apps }
                Divider()
                SettingsDetailLink(title: "Приватность macOS") { topic = .privacy }
            }
            EngineSection(title: "Дополнительно") {
                SettingsDetailLink(title: "Проверка BIN карты") { topic = .bin }
                Divider()
                SettingsDetailLink(title: "Платёжный адрес") { topic = .address }
                Divider()
                SettingsDetailLink(title: "О проекте и источниках") { topic = .project }
            }
        }
        .sheet(item: $topic) { selection in
            SettingsDetailSheet(title: selection.rawValue) {
                switch selection {
                case .connection:
            EngineSection(title: "Свой сервер и VPN") {
                Text("1. Выберите VPS и страну, доступную нужному сервису, по его официальным условиям.")
                Text("2. Установите VPN по инструкции его разработчика. Сохраните резервный доступ к серверу.")
                Text("3. Подключите VPN и выполните проверки выхода в Russian Armor.")
                Text("4. Для выделенного прокси добавьте адрес в «Маршрутах» и проверьте выход перед назначением сервису.")
                Link("Документация Amnezia", destination: URL(string: "https://docs.amnezia.org/")!)
                Link("Документация Xray", destination: URL(string: "https://xtls.github.io/")!)
                Text("Выделенный сервер не исключает ограничения аккаунта.")
                    .font(.caption).foregroundStyle(.secondary)
            }
                case .apps:
            EngineSection(title: "Подключение приложений") {
                Text("Включите прокси и CLI в «Сетевом шлюзе», затем откройте «Приложения»: там указаны действия для каждого клиента и фактический статус покрытия.")
                Text("Для ручного запуска CLI задайте HTTP_PROXY и HTTPS_PROXY только для нужной команды. NO_PROXY оставьте для localhost и локальной сети.")
                if engine.connected, engine.coverage["gateway_addr"].optionalString != nil {
                    let command = "HTTPS_PROXY=http://\(engine.gateway) HTTP_PROXY=http://\(engine.gateway) NO_PROXY=localhost,127.0.0.1,::1 claude"
                    Text(engine.display(command)).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    Button("Скопировать команду запуска Claude Code") {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(command, forType: .string)
                    }
                }
            }
                case .privacy:
            EngineSection(title: "Приватность macOS") {
                Text("Проверьте разрешения геолокации для браузеров и ИИ-клиентов в системных настройках. Диагностика окружения не доказывает, что сервис определяет местоположение именно этим способом.")
                Button("Открыть настройки геолокации") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices")!)
                }
                Text("В Russian Armor можно отдельно синхронизировать окружение ИИ и системный часовой пояс. Последний влияет на весь Mac и требует отдельного действия.")
            }
                case .bin:
            EngineSection(title: "Проверка BIN карты") {
                Text("Проверяются только первые 6 цифр: страна, тип и банк из справочника. Это не проверка возможности оплаты конкретной подписки. Если локального ответа нет, эти цифры отправляются в data.handyapi.com.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Первые 6 цифр карты", text: Binding(get: { bin }, set: { bin = String($0.filter { $0.isASCII && $0.isNumber }.prefix(6)) }))
                    .textFieldStyle(.roundedBorder)
                Button(checking ? "Проверяем…" : "Проверить BIN") {
                    checking = true; failed = false; result = .null
                    Task {
                        defer { checking = false }
                        do { result = try await engine.call("check_payment_bin", ["bin": .string(bin), "vpnCountry": .null]) }
                        catch { failed = true }
                    }
                }.disabled(bin.count != 6 || checking || !engine.connected)
                if !engine.connected { Text("Для проверки запустите сетевой модуль.").font(.caption).foregroundStyle(.secondary) }
                if failed { Text("Данные не получены. BIN не проверен.").foregroundStyle(.secondary) }
                if case .object = result {
                    LabeledContent("Страна", value: result["country_code"].optionalString ?? "Нет данных")
                    LabeledContent("Банк", value: result["bank_name"].optionalString ?? "Нет данных")
                    LabeledContent("Тип", value: result["card_type"].optionalString ?? "Нет данных")
                    Text(engine.display(result["advisory"].string)).font(.caption).foregroundStyle(.secondary)
                }
                Text("Для оплаты используйте адрес из реквизитов своего банка.")
                    .font(.caption).foregroundStyle(.secondary)
            }
                case .project:
            EngineSection(title: "О проекте и источниках") {
                Text("Сетевой модуль основан на ai-antiban / «Заставе» v2.3.0, распространяемой по MIT. Авторские уведомления и исходная лицензия сохранены.")
                    .font(.caption).foregroundStyle(.secondary)
                Link("Исходный проект и лицензия", destination: URL(string: "https://github.com/kingbest1195/ai-antiban")!)
                Link("Поддержка Russian Armor", destination: URL(string: "https://github.com/danielsuchx/russian-armor/issues")!)
            }
                case .address:
            EngineSection(title: "Платёжный адрес") {
                Text("Соберите адрес из реквизитов своего банка. Поля хранятся только в памяти этого окна и не отправляются на проверку.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Улица и дом", text: $street).textFieldStyle(.roundedBorder)
                TextField("Город", text: $city).textFieldStyle(.roundedBorder)
                TextField("Регион / штат", text: $region).textFieldStyle(.roundedBorder)
                TextField("Почтовый индекс", text: $postalCode).textFieldStyle(.roundedBorder)
                TextField("Страна", text: $country).textFieldStyle(.roundedBorder)
                Button("Скопировать полный адрес") {
                    let address = [street, city, region, postalCode, country].filter { !$0.isEmpty }.joined(separator: ", ")
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(address, forType: .string)
                }.disabled(street.isEmpty || city.isEmpty || country.isEmpty)
            }                }
            }
        }
    }
}
