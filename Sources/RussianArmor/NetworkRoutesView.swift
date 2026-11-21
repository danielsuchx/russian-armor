import SwiftUI

struct NetworkRoutesView: View {
    @ObservedObject var engine: NetworkEngineStore
    @State private var key = ""
    @State private var showsImport = false
    @State private var importError: String?
    @State private var adding = false
    @State private var removing: EngineValue?
    @State private var results: [String: EngineValue] = [:]
    @State private var testing = Set<String>()

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack {
                Text("Прокси для выхода к ИИ-сервисам").foregroundStyle(.secondary)
                Spacer()
                Button("Добавить маршрут…") { showsImport = true }
            }
            EngineSection(title: "Выход по умолчанию") {
                routePicker("Общий маршрут", selected: engine.routes["default_route_id"].string, inherit: "Системная сеть", direct: false) {
                    engine.perform("set_default_route", args: ["routeId": .optional($0.isEmpty ? nil : $0)])
                }
                Text("Системная сеть использует VPN этого Mac. Недоступный прокси блокирует выход через него.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            EngineSection(title: "Маршруты сервисов") {
                ForEach(NetworkEngineStore.providers, id: \.0) { provider, name in
                    routePicker(name, selected: engine.routes["provider_routes"][provider].string) {
                        engine.perform("bind_provider_route", args: ["provider": .string(provider), "routeId": .optional($0.isEmpty ? nil : $0)])
                    }
                }
                if engine.routes["profile_route_id"].optionalString != nil {
                    Text("Для Claude действует маршрут активного профиля; он имеет приоритет над настройкой сервиса.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let error = engine.routes["profile_route_error"].optionalString {
                    Label(engine.display(error), systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                }
                if !engine.routes["dangling"].array.isEmpty {
                    Label("Есть привязки к удалённым маршрутам. Выберите новый маршрут для соответствующего сервиса.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }
            ForEach(engine.routeItems, id: \.["id"].string) { route in
                EngineSection(title: engine.display(route["label"].string)) {
                    HStack {
                        Text(routeStatus(route)).foregroundStyle(.secondary)
                        Spacer()
                        Toggle("Включён", isOn: Binding(get: { route["enabled"].bool }, set: {
                            engine.perform("set_route_enabled", args: ["id": route["id"], "enabled": .bool($0)])
                        })).toggleStyle(.switch)
                    }
                    DisclosureGroup("Адрес и срок действия") {
                        VStack(alignment: .leading, spacing: 6) {
                    if let country = route["country"].optionalString { Text("Страна маршрута: \(country)") }
                    if let ip = route["exit_ip"].optionalString { Text("Заявленный выход: \(engine.display(ip))").textSelection(.enabled) }
                    ForEach(Array(route["entries"].array.enumerated()), id: \.offset) { _, entry in
                        Text(engine.display("\(entry["proto"].string) · \(entry["host"].string):\(Int(entry["port"].number))"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if route["expires_at"].number > 0 {
                        Text("Действует до \(Date(timeIntervalSince1970: route["expires_at"].number).formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                        }.padding(.top, 6)
                    }
                    if let result = results[route["id"].string] {
                        Text(result["ok"].bool
                             ? "Выход: \(engine.display(result["exit_ip"].string)) · \(result["country"].string) · \(Int(result["latency_ms"].number)) мс"
                             : EnginePrivacy.display(result["error"].optionalString ?? "Маршрут не подтвердил выход", hideAddresses: engine.hideIP))
                            .font(.caption).foregroundStyle(result["ok"].bool ? Color.secondary : .orange)
                    }
                    HStack {
                        Button(testing.contains(route["id"].string) ? "Проверяем…" : "Проверить выход") { test(route) }
                            .disabled(testing.contains(route["id"].string))
                        Spacer()
                        Button("Удалить…", role: .destructive) { removing = route }
                    }
                }
            }
        }
        .sheet(isPresented: $showsImport) {
            SettingsDetailSheet(title: "Добавить маршрут", height: 280) {
            EngineSection(title: "Адрес или ключ прокси") {
                SecureField("zastava://, socks5://, http:// или https://", text: $key)
                    .textFieldStyle(.roundedBorder)
                Text("Ключи и пароли сохраняются локально, без шифрования Keychain.")
                    .font(.caption).foregroundStyle(.secondary)
                Button(adding ? "Добавляем…" : "Добавить") { add() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(key.isEmpty || adding)
                if let importError { Text(importError).foregroundStyle(.orange) }
            }
            }
        }
        .alert("Удалить маршрут?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Отмена", role: .cancel) { removing = nil }
            Button("Удалить", role: .destructive) {
                if let route = removing { engine.perform("remove_route", args: ["id": route["id"]]) }
                removing = nil
            }
        } message: { Text("Связанные сервисы могут остаться заблокированными до выбора нового маршрута.") }
        .onAppear { if let candidate = engine.importedRoute { key = candidate; showsImport = true; engine.importedRoute = nil } }
        .onChange(of: engine.importedRoute) { candidate in
            if let candidate { key = candidate; showsImport = true; engine.importedRoute = nil }
        }
    }

    private func routePicker(_ title: String, selected: String, inherit: String = "Общий маршрут", direct: Bool = true,
                             changed: @escaping (String) -> Void) -> some View {
        Picker(title, selection: Binding(get: { selected }, set: changed)) {
            Text(inherit).tag("")
            if direct { Text("Системная сеть, без общего маршрута").tag("__direct__") }
            ForEach(engine.routeItems, id: \.["id"].string) { route in
                Text(engine.display(route["label"].string)).tag(route["id"].string)
            }
            if !selected.isEmpty && selected != "__direct__" && !engine.routeItems.contains(where: { $0["id"].string == selected }) {
                Text("Недоступный маршрут").tag(selected)
            }
        }
    }
    private func routeStatus(_ route: EngineValue) -> String {
        switch route["status"].string {
        case "disabled": return "Выключен"
        case "expired": return "Срок действия истёк"
        case "unreachable": return "Недоступен"
        case "exit_ip_mismatch": return "IP выхода не совпал"
        default: return route["health"]["checked_at"].number > 0 ? "Есть результат проверки" : "Выход ещё не проверен"
        }
    }
    private func add() {
        adding = true; importError = nil
        let candidate = key
        Task {
            defer { adding = false }
            do { _ = try await engine.call("add_route", ["key": .string(candidate)]); key = ""; showsImport = false; await engine.refresh() }
            catch { importError = (error as? NetworkEngineError)?.errorDescription ?? "Не удалось импортировать маршрут." }
        }
    }
    private func test(_ route: EngineValue) {
        let id = route["id"].string
        testing.insert(id); results[id] = nil
        Task {
            defer { testing.remove(id) }
            do { results[id] = try await engine.call("test_route", ["id": .string(id)]); await engine.refresh() }
            catch { results[id] = .object(["ok": .bool(false), "error": .string("Проверка маршрута не завершена")]) }
        }
    }
}
