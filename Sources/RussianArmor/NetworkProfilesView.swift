import AppKit
import ArmorCore
import SwiftUI

struct NetworkProfilesView: View {
    @ObservedObject var engine: NetworkEngineStore
    @State private var name = ""
    @State private var showsCreate = false
    @State private var pending: ProfileAction?
    @State private var editing: ProfileEdit?
    @State private var summary: EngineValue = .null
    @State private var archive: EngineValue = .null
    @State private var archiving = false
    @State private var archiveError = ""

    private struct ProfileAction: Identifiable {
        let id = UUID()
        let command: String
        let args: [String: EngineValue]
        let title: String
        let detail: String
    }
    private struct ProfileEdit: Identifiable { let value: EngineValue; var id: String { value["id"].string } }

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            EngineSection(title: "Профили Claude Desktop") {
                HStack {
                    Text("Отдельная сессия и маршрут для каждого профиля.")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Новый профиль…") { showsCreate = true }
                }
                ForEach(engine.profileItems, id: \.["id"].string) { profile in
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(engine.display(profile["name"].string)).fontWeight(.semibold)
                            if profile["is_active"].bool { Text("Активный").font(.caption).foregroundStyle(.secondary) }
                            Spacer()
                        }
                        if let ip = profile["bound_ip"].optionalString { Text("Привязка IP: \(engine.display(ip)) · \(profile["bound_country"].string)").font(.caption) }
                        if let route = profile["bound_route_id"].optionalString {
                            let label = engine.routeItems.first { $0["id"].string == route }?["label"].string ?? "Недоступный маршрут"
                            Text("Маршрут: \(engine.display(label))").font(.caption)
                        }
                        HStack {
                            Button("IP и маршрут…") { editing = .init(value: profile) }
                            Button("Переключиться…") {
                                pending = .init(command: "switch_claude_profile_cmd", args: ["targetId": profile["id"]],
                                                title: "Переключить профиль Claude?", detail: "Claude будет закрыт. Текущая сессия сохранится, затем будет восстановлена сессия выбранного профиля.")
                            }.disabled(profile["is_active"].bool)
                            Spacer()
                            if profile["id"].string != "default" {
                                Button("Удалить…", role: .destructive) {
                                    pending = .init(command: "delete_claude_profile_cmd", args: ["profileId": profile["id"]],
                                                    title: "Удалить профиль?", detail: "Сохранённая локальная сессия этого профиля будет удалена. Активный профиль может быть переключён.")
                                }
                            }
                        }
                    }
                }
            }
            EngineSection(title: "Архив Claude Code") {
                Text("Проекты, сессии и память Claude Code. Архив содержит данные вашей работы.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Посмотреть локальные данные") { Task { summary = (try? await engine.call("scan_claude_data_cmd")) ?? .null } }
                if case .object = summary {
                    Text("Проектов: \(Int(summary["projects_count"].number)) · сессий: \(Int(summary["sessions_count"].number)) · файлов памяти: \(Int(summary["memory_files_count"].number))")
                    Text("Объём: \(ByteCountFormatter.string(fromByteCount: Int64(summary["total_size_bytes"].number), countStyle: .file))").font(.caption).foregroundStyle(.secondary)
                }
                Button(archiving ? "Создаём архив…" : "Создать локальный архив", action: makeArchive).disabled(archiving)
                if !archiveError.isEmpty { Text(archiveError).foregroundStyle(.orange) }
                if let path = archive["zip_archive_path"].optionalString ?? archive["export_dir_path"].optionalString {
                    Text("Архив создан").fontWeight(.medium)
                    HStack {
                        Button("Показать в Finder") { NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "") }
                        Button("Скопировать промпт восстановления") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(archive["restore_prompt_text"].string, forType: .string)
                        }
                    }
                }
            }
            EngineSection(title: "Выход перед сменой сети") {
                Button("Безопасно выйти из Claude…") {
                    pending = .init(command: "safe_logout_claude_cmd", args: [:], title: "Закрыть Claude и очистить сессию?",
                                    detail: "Будут закрыты процессы Claude и очищены данные авторизации. Идентификатор устройства и настройки MCP сохраняются. Начнётся четырёхчасовой таймер смены сети.")
                }
                if engine.state["ip_change_cooldown_until"].number > Date().timeIntervalSince1970 {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let remaining = max(0, Int(engine.state["ip_change_cooldown_until"].number - context.date.timeIntervalSince1970))
                        Text("До завершения паузы: \(remaining / 3600) ч \((remaining % 3600) / 60) мин")
                            .font(.caption).monospacedDigit()
                    }
                }
                Button("Сбросить таймер…") {
                    pending = .init(command: "clear_ip_change_cooldown_cmd", args: [:], title: "Сбросить таймер смены сети?",
                                    detail: "Дополнительное ограничение времени будет снято. Остальные проверки продолжают действовать.")
                }
            }
            DisclosureGroup("Таймер аккаунта и очистка данных") {
                VStack(alignment: .leading, spacing: 20) {
            EngineSection(title: "Таймер подготовки аккаунта") {
                if engine.state["warmup_started_at"].number > 0 {
                    let start = Date(timeIntervalSince1970: engine.state["warmup_started_at"].number)
                    Text("Начало: \(start.formatted(date: .abbreviated, time: .shortened))")
                    Button("Сбросить таймер") { engine.perform("set_warmup_timer", args: ["timestamp": .null]) }
                } else {
                    Button("Запустить таймер") { engine.perform("set_warmup_timer", args: ["timestamp": .number(Date().timeIntervalSince1970.rounded(.down))]) }
                }
                Text("Таймер не подтверждает готовность аккаунта к оплате.").font(.caption).foregroundStyle(.secondary)
            }
            EngineSection(title: "Очистка данных клиентов") {
                ForEach([( "anthropic", "Claude"), ("openai", "ChatGPT")], id: \.0) { id, title in
                    Button("Очистить данные \(title)…", role: .destructive) {
                        pending = .init(command: "clean_app_cache", args: ["provider": .string(id)], title: "Очистить данные \(title)?",
                                        detail: "Будут удалены cookies, локальное хранилище, кэш и часть настроек клиента. Может потребоваться повторный вход. Предварительно закройте клиент.")
                    }
                }
            }                }.padding(.top, 12)
            }

        }
        .alert(pending?.title ?? "Подтверждение", isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } })) {
            Button("Отмена", role: .cancel) { pending = nil }
            Button("Продолжить") { if let action = pending { engine.perform(action.command, args: action.args) }; pending = nil }
        } message: { Text(pending?.detail ?? "") }
        .sheet(isPresented: $showsCreate) {
            SettingsDetailSheet(title: "Новый профиль Claude", height: 260) {
                TextField("Название профиля", text: $name).textFieldStyle(.roundedBorder)
                Text("Переключение профилей закрывает Claude и сохраняет текущую сессию.").foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Создать") {
                        engine.perform("create_claude_profile_cmd", args: ["name": .string(name)])
                        name = ""; showsCreate = false
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .sheet(item: $editing) { NativeProfileBindingView(engine: engine, profile: $0.value) }
    }
    private func makeArchive() {
        archiving = true; archiveError = ""
        Task {
            defer { archiving = false }
            do { archive = try await engine.call("export_claude_data_cmd") }
            catch { archiveError = "Архив не создан. Проверьте доступ к локальным данным и свободное место." }
        }
    }
}

private struct NativeProfileBindingView: View {
    @ObservedObject var engine: NetworkEngineStore
    let profile: EngineValue
    @Environment(\.dismiss) private var dismiss
    @State private var ip = ""
    @State private var country = ""
    @State private var route = ""
    @State private var busy = false
    @State private var error = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Привязка профиля").font(.title2.weight(.semibold))
            TextField("Ожидаемый IP, необязательно", text: $ip).textFieldStyle(.roundedBorder)
            TextField("Код страны, например NL", text: $country).textFieldStyle(.roundedBorder)
            Picker("Маршрут", selection: $route) {
                Text("Маршрут сервиса").tag("")
                ForEach(engine.routeItems, id: \.["id"].string) { item in Text(engine.display(item["label"].string)).tag(item["id"].string) }
            }
            Text("Изменение привязки активного профиля применяется к его сетевым настройкам.").font(.caption).foregroundStyle(.secondary)
            if !error.isEmpty { Text(error).foregroundStyle(.orange) }
            HStack {
                Button("Отмена") { dismiss() }
                Spacer()
                Button("Сохранить") {
                    busy = true
                    Task {
                        defer { busy = false }
                        do {
                            _ = try await engine.call("bind_ip_to_claude_profile_cmd", ["profileId": profile["id"],
                                "bindIp": .optional(ip.isEmpty ? nil : ip), "bindCountry": .optional(country.isEmpty ? nil : country.uppercased())])
                            _ = try await engine.call("bind_route_to_claude_profile", ["profileId": profile["id"], "routeId": .optional(route.isEmpty ? nil : route)])
                            await engine.refresh(); dismiss()
                        } catch { self.error = "Не удалось сохранить привязку. Проверьте данные и повторите попытку." }
                    }
                }.disabled(busy || (!ip.isEmpty && !IPRange.isValidAddress(ip)) || (!country.isEmpty && country.utf8.count != 2))
            }
        }.padding(24).frame(width: 460)
        .onAppear { ip = profile["bound_ip"].string; country = profile["bound_country"].string; route = profile["bound_route_id"].string }
    }
}
