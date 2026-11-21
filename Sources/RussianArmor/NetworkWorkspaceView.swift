import AppKit
import SwiftUI

struct EngineSection<Content: View>: View {
    let title: String
    @ViewBuilder var content: () -> Content
    var body: some View {
        SettingsCard(title: title, content: content)
    }
}

struct NetworkWorkspaceView: View {
    @ObservedObject var engine: NetworkEngineStore
    let section: SettingsSection
    @State private var showsStartupDetails = false
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if let error = engine.error {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let notice = engine.notice { Text(notice).foregroundStyle(.secondary) }
            if section == .guides {
                NetworkGuidesView(engine: engine)
            } else if !engine.connected {
                EngineSection(title: "") {
                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: "network").font(.system(size: 28)).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Сетевой модуль выключен").font(.system(size: 16, weight: .semibold))
                            Text("Подключите его для настройки маршрутов и проверки приложений.")
                                .foregroundStyle(.secondary)
                            HStack {
                                Button(engine.starting ? "Запускаем…" : "Включить модуль") { Task { await engine.start() } }
                                    .buttonStyle(.borderedProminent).disabled(engine.starting)
                                    .accessibilityIdentifier("network-engine-start")
                                Button("Подробнее…") { showsStartupDetails = true }.buttonStyle(.link)
                            }
                        }
                    }
                }
            } else {
                switch section {
                case .network: NetworkGatewayView(engine: engine)
                case .routes: NetworkRoutesView(engine: engine)
                case .audit: NetworkAuditView(engine: engine)
                case .coverage: NetworkCoverageView(engine: engine)
                case .backup: NetworkProfilesView(engine: engine)
                default: EmptyView()
                }
            }
        }
        .sheet(isPresented: $showsStartupDetails) {
            SettingsDetailSheet(title: "Сетевой модуль", height: 420) {
                SettingsCard(title: "Что включается") {
                    Text("Локальный шлюз и проверки соединений Claude, ChatGPT и Gemini.")
                    Text("Прокси, настройка терминала и часовой пояс включаются отдельно. При повторном запуске применяются сохранённые настройки. При отключении собственные изменения восстанавливаются.")
                }
                SettingsCard(title: "Локальные данные") {
                    Text("История выходных IP и ключи прокси сохраняются на этом Mac в файле с доступом только для пользователя, без шифрования Keychain.")
                }
            }
        }
        .onAppear { if engine.connected { Task { await engine.refresh() } } }
    }
}

struct NetworkGatewayView: View {
    @ObservedObject var engine: NetworkEngineStore
    @State private var preview: [EngineValue] = []
    @State private var timezone = ""
    @State private var domain = ""
    @State private var confirmGlobal = false
    @State private var confirmsOSClock = false
    @State private var confirmsCleanup = false
    @State private var confirmsStop = false
    @State private var export: String?
    @State private var testRunning = false
    @State private var testResult = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            EngineSection(title: "") {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: engine.pause["manual_killswitch"].bool || engine.pause["paused"].bool ? "pause.circle" : "network")
                        .font(.system(size: 24)).foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(engine.pause["manual_killswitch"].bool ? "Трафик остановлен" :
                                engine.pause["paused"].bool ? "Доступ приостановлен" :
                                engine.pause["gate"].string == "open" ? "Шлюз передаёт трафик" : "Ожидает проверки")
                            .font(.system(size: 16, weight: .semibold))
                        if let reason = engine.pause["gate_reason"].optionalString, !reason.isEmpty {
                            Text(engine.display(reason)).font(.caption).foregroundStyle(.secondary)
                        }
                        Text("Только соединения через шлюз").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                    Button(engine.pause["manual_killswitch"].bool ? "Возобновить" : "Остановить") {
                        engine.perform("toggle_network_killswitch_cmd", args: ["freeze": .bool(!engine.pause["manual_killswitch"].bool)])
                    }
                }
                Divider()
                SettingsToggle(title: "Браузеры и приложения", detail: "Системный прокси", isOn: Binding(get: { engine.sysproxy }, set: {
                    engine.perform("toggle_sysproxy", args: ["enable": .bool($0)])
                })).disabled(engine.busy.contains("toggle_sysproxy"))
                Divider()
                SettingsToggle(title: "Терминал и редакторы", detail: "Настройка ИИ-клиентов", isOn: Binding(get: { engine.cliEnabled }, set: {
                    engine.perform($0 ? "enable_cli_protection" : "disable_cli_protection")
                })).disabled(engine.busy.contains("enable_cli_protection") || engine.busy.contains("disable_cli_protection"))
            }
            EngineSection(title: "При изменении сети") {
                Picker("Действие", selection: Binding(get: { engine.state["interception_behavior"].optionalString ?? "ask_popup" }, set: {
                    engine.perform("set_interception_behavior_cmd", args: ["behavior": .string($0)])
                })) {
                    Text("Запросить решение").tag("ask_popup")
                    Text("Блокировать без окна").tag("auto_lock_silent")
                    Text("Разрешать доверенные страны").tag("auto_allow_trusted")
                }
            }
            Text("Проверить, какие приложения используют шлюз, можно в разделе «Приложения».")
                .font(.caption).foregroundStyle(.secondary)
            DisclosureGroup("Дополнительные настройки") {
                VStack(alignment: .leading, spacing: 20) {
                    EngineSection(title: "Уведомления и VPN") {
                        Picker("Положение уведомления", selection: Binding(get: { engine.state["popup_position"].optionalString ?? "top_right" }, set: {
                            engine.perform("set_popup_position_cmd", args: ["position": .string($0)])
                        })) {
                            Text("Справа вверху").tag("top_right")
                            Text("По центру вверху").tag("top_center")
                        }
                        Button("Тестовое уведомление") { engine.perform("simulate_interception", args: ["provider": .string("anthropic")]) }
                        Toggle("Выборочная маршрутизация VPN", isOn: Binding(get: { engine.state["split_tunnel_mode"].bool }, set: {
                            engine.perform("set_split_tunnel_mode", args: ["enabled": .bool($0)])
                        }))
                        Button("Пауза до смены сети") { engine.perform("pause_until_network_change_cmd") }
                        if !engine.sysproxy {
                            Button("Настроить прокси с правами администратора…") { engine.perform("toggle_sysproxy_privileged") }
                        }
                    }
            EngineSection(title: "Терминал и часовой пояс") {
                Picker("Область настройки", selection: Binding(get: { engine.cli["cli_mode"].optionalString ?? "ai_only" }, set: {
                    if $0 == "global_terminal" { confirmGlobal = true }
                    else { engine.perform("set_cli_mode", args: ["mode": .string($0)]) }
                })) {
                    Text("Только ИИ-клиенты").tag("ai_only")
                    Text("Весь терминал").tag("global_terminal")
                }
                Toggle("Синхронизировать часовой пояс для ИИ", isOn: Binding(get: { engine.cli["sync_ai_tz_enabled"].bool }, set: {
                    engine.perform("set_sync_ai_tz_enabled", args: ["enabled": .bool($0)])
                }))
                TextField("Часовой пояс, например Europe/Amsterdam", text: $timezone)
                    .textFieldStyle(.roundedBorder)
                Button("Применить для ИИ") {
                    engine.perform("sync_ai_agents_timezone", args: ["timezone": .string(timezone)])
                }.disabled(!TimeZone.knownTimeZoneIdentifiers.contains(timezone))
                GroupBox("Часовой пояс macOS") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Влияет на весь Mac. Исходное значение восстановится при отключении модуля.").font(.caption)
                        Button("Изменить часовой пояс macOS…") { confirmsOSClock = true }
                            .disabled(!timezone.isEmpty && !TimeZone.knownTimeZoneIdentifiers.contains(timezone))
                        Button("Восстановить исходный пояс") { engine.perform("restore_os_timezone_cmd") }
                        Button("Открыть настройки даты и времени") { engine.perform("open_os_datetime_settings_cmd") }
                    }.padding(.top, 8)
                }
            }
            EngineSection(title: "Изменения системы и диагностика") {
                LabeledContent("Активные ИИ-соединения", value: String(Int(engine.stats["active_ai_tunnels"].number)))
                LabeledContent("Запросы через шлюз", value: String(Int(engine.stats["protected_ai_requests"].number)))
                Button("Показать настройки, которые будут изменены") {
                    Task {
                        if let result = try? await engine.call("preview_protection_changes_cmd") { preview = result.array }
                    }
                }
                ForEach(Array(preview.enumerated()), id: \.offset) { _, item in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(item["target"].string).fontWeight(.medium)
                        Text(engine.display(item["description"].string)).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Button("Подготовить очищенный отчёт…") {
                    Task { export = try? await engine.call("export_diagnostic_bundle_cmd").optionalString }
                }
                Text("При подготовке этого отчёта модуль может повторить сетевые проверки для трёх сервисов.")
                    .font(.caption).foregroundStyle(.secondary)
                Button(testRunning ? "Тестируем…" : "Тест обрыва на тестовом соединении", action: runSelfTest).disabled(testRunning)
                if !testResult.isEmpty { Text(engine.display(testResult)).font(.caption) }
                Button("Восстановить настройки прокси…") { confirmsCleanup = true }
            }
            EngineSection(title: "Мониторинг и домены") {
                ForEach(NetworkEngineStore.providers, id: \.0) { id, name in
                    Toggle(name, isOn: Binding(get: {
                        !engine.state["disabled_providers"].array.contains(.string(id))
                    }, set: { engine.perform("set_provider_monitoring", args: ["provider": .string(id), "enabled": .bool($0)]) }))
                }
                HStack {
                    TextField("Дополнительный домен ИИ", text: $domain).textFieldStyle(.roundedBorder)
                    Button("Добавить") {
                        engine.perform("add_custom_ai_domain_cmd", args: ["domain": .string(domain)])
                        domain = ""
                    }.disabled(domain.isEmpty)
                }
                ForEach(engine.state["custom_ai_domains"].array.map(\.string), id: \.self) { name in
                    HStack { Text(name); Spacer(); Button("Удалить") { engine.perform("remove_custom_ai_domain_cmd", args: ["domain": .string(name)]) } }
                }
                ForEach(engine.state["trusted_exceptions"].object.keys.sorted(), id: \.self) { provider in
                    ForEach(engine.state["trusted_exceptions"][provider].array.map(\.string), id: \.self) { ip in
                        HStack {
                            Text("\(provider): \(engine.display(ip))")
                            Spacer()
                            Button("Убрать исключение") { engine.perform("remove_trusted_exception", args: ["provider": .string(provider), "ip": .string(ip)]) }
                        }
                    }
                }
            }
            EngineSection(title: "Сетевой модуль") {
                Text("При отключении восстановятся настройки прокси и окружения. Защита процессов Claude останется включённой.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Отключить сетевой модуль…") { confirmsStop = true }
            }                }.padding(.top, 12)
            }

        }
        .alert("Настроить прокси для всего терминала?", isPresented: $confirmGlobal) {
            Button("Отмена", role: .cancel) {}
            Button("Настроить") { engine.perform("set_cli_mode", args: ["mode": .string("global_terminal")]) }
        } message: { Text("В профили оболочки будет добавлен управляемый блок. Его начнут использовать новые окна терминала, включая обычные CLI-команды.") }
        .alert("Изменить часовой пояс macOS?", isPresented: $confirmsOSClock) {
            Button("Отмена", role: .cancel) {}
            Button("Изменить") { engine.perform("sync_os_timezone_cmd", args: ["targetTz": .optional(timezone.isEmpty ? nil : timezone)]) }
        }
        .alert("Восстановить настройки прокси?", isPresented: $confirmsCleanup) {
            Button("Отмена", role: .cancel) {}
            Button("Восстановить") { engine.perform("force_clean_os_proxy_cmd") }
        } message: { Text("Сетевая защита через прокси будет отключена. Проверьте VPN перед продолжением работы.") }
        .sheet(isPresented: Binding(get: { export != nil }, set: { if !$0 { export = nil } })) {
            EngineTextExportView(text: export ?? "", filename: "Russian-Armor-network-diagnostics.json")
        }
        .alert("Восстановить настройки и отключить шлюз?", isPresented: $confirmsStop) {
            Button("Отмена", role: .cancel) {}
            Button("Отключить") {
                Task { try? await engine.shutdown(preservePreference: false) }
            }
        }
    }

    private func runSelfTest() {
        testRunning = true; testResult = ""
        Task {
            defer { testRunning = false }
            do {
                let before = try await engine.call("run_vpn_crash_test_step")
                _ = try await engine.call("trigger_crash_test_drop")
                let during = try await engine.call("run_vpn_crash_test_step")
                _ = try await engine.call("reset_crash_test_drop")
                let after = try await engine.call("run_vpn_crash_test_step")
                testResult = "До: \(before["status_text"].string). При обрыве: \(during["status_text"].string). После: \(after["status_text"].string). Это тест шлюза, не гарантия отсутствия утечек."
            } catch {
                _ = try? await engine.call("reset_crash_test_drop")
                testResult = "Тест не завершён. Работа шлюза этим тестом не подтверждена."
            }
        }
    }
}
