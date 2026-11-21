import ArmorCore
import SwiftUI

enum SettingsLayout {
    static let defaultSize = NSSize(width: 820, height: 680)
    static let minimumSize = NSSize(width: 760, height: 600)
    static let sidebarWidth: CGFloat = 184
}

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: SettingsSection?
    @State private var showsRules = false
    @State private var showsPrivacy = false
    private let openHistory: () -> Void

    init(initialSection: SettingsSection = .protection, openHistory: @escaping () -> Void = {}) {
        _selection = State(initialValue: initialSection)
        self.openHistory = openHistory
    }

    private var section: SettingsSection { selection ?? .protection }
    private var status: SettingsProtectionContent {
        SettingsProtectionContent(protection: model.protection, isSleeping: model.isSleeping)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text(section.title).font(.system(size: 20, weight: .semibold))
                        .accessibilityAddTraits(.isHeader)
                    Spacer()
                    if model.networkEngine.connected, [.network, .routes, .coverage, .backup].contains(section) {
                        Button { Task { await model.networkEngine.refresh() } } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .buttonStyle(.borderless)
                        .help("Обновить данные")
                        .accessibilityLabel("Обновить данные")
                    }
                }
                .padding(.horizontal, 24).padding(.vertical, 18)
                // Keep each page mounted so navigation preserves scroll position,
                // discovered tunnels and an in-flight self-test's result.
                ZStack(alignment: .topLeading) {
                    ForEach(SettingsSection.allCases) { page in
                        settingsPage(page)
                            .opacity(page == section ? 1 : 0)
                            .allowsHitTesting(page == section)
                            .disabled(page != section)
                            .accessibilityHidden(page != section)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .frame(minWidth: SettingsLayout.minimumSize.width, minHeight: SettingsLayout.minimumSize.height)
        .modifier(NetworkPrivacyModifier(engine: model.networkEngine))
        .sheet(isPresented: $showsRules) {
            AccessRulesEditor(configuration: model.accessConfiguration).environmentObject(model)
                .modifier(NetworkPrivacyModifier(engine: model.networkEngine))
        }
        .sheet(isPresented: $showsPrivacy) {
            SettingsDetailSheet(title: "Хранение данных", height: 340) {
                SettingsCard(title: "На этом Mac") {
                    Text("Настройки и до \(EventJournal.capacity) событий процессной защиты хранятся локально. Наблюдаемые ею IP остаются в памяти; адреса в правилах допуска сохраняются.")
                    Text("Сетевой модуль сохраняет историю выходных IP и ключи прокси в файле с доступом только для пользователя, без шифрования Keychain.")
                }
            }
        }
        .onChange(of: model.requestedSettingsSection) { destination in
            if let destination { selection = destination }
        }
        .onChange(of: selection) { destination in
            if model.requestedSettingsSection != destination { model.requestedSettingsSection = destination }
        }
    }

    private func settingsPage(_ page: SettingsSection) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if let warning = model.storageWarning {
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                    switch page {
                    case .protection:
                        protectionContent {
                            withAnimation { proxy.scrollTo("access-rules", anchor: .top) }
                        }
                    case .diagnostics:
                        diagnosticsContent
                    case .general:
                        generalContent
                    case .network, .routes, .audit, .coverage, .backup, .guides:
                        NetworkWorkspaceView(engine: model.networkEngine, section: page)
                    }
                }
                .font(.system(size: 13))
                .frame(maxWidth: 660, alignment: .leading)
                .padding(.horizontal, 24).padding(.bottom, 24)
                .frame(maxWidth: .infinity, alignment: .top)
            }
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            List(selection: $selection) {
                ForEach(Array(SettingsSection.navigationGroups.enumerated()), id: \.offset) { _, group in
                    Section(group.0) {
                        ForEach(group.1) { section in
                            Label(section.title, systemImage: section.symbol)
                                .padding(.vertical, 3)
                                .tag(section)
                                .accessibilityIdentifier("settings-section-\(section.rawValue)")
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            // Use the container's background through the list, its top inset
            // and the footer instead of painting three separate surfaces.
            .scrollContentBackground(.hidden)
            .accessibilityLabel("Разделы настроек")
            .padding(.top, 12)
            Label("Russian Armor", systemImage: "shield.lefthalf.filled")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
                .padding(16)
        }
        .frame(width: SettingsLayout.sidebarWidth)
        .background(.quaternary.opacity(0.4))
    }

    private func protectionContent(chooseRules: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 22) {
            protectionStatus(chooseRules: chooseRules)
            ClaudeProtectionView(filter: model.claudeFilter)

            settingsGroup("Подключение") {
                Picker("Где работает VPN", selection: $model.preferences.vpnLocation) {
                    ForEach(VPNLocation.allCases, id: \.self) { location in
                        Text(location.title).tag(location)
                    }
                }
                .accessibilityIdentifier("settings-vpn-location")
                Text(connectionGuidance).foregroundStyle(.secondary)
                if model.preferences.vpnLocation == .thisMac {
                    TunnelSelectionView()
                    settingsSwitch("Показывать имена туннелей", isOn: $model.preferences.showInterfaceNames)
                }
            }

            settingsGroup("Правила допуска") {
                if model.accessConfiguration.isValid, let profile = model.accessConfiguration.activeProfile {
                    valueRow("Активный профиль", value: profile.name)
                    if profile.rules(for: .desktop) != profile.rules(for: .code) {
                        ruleSummary("Claude Desktop", rules: profile.rules(for: .desktop))
                        Divider()
                        ruleSummary("Claude Code", rules: profile.rules(for: .code))
                    } else {
                        ruleSummary("Claude Desktop и Code", rules: profile.rules(for: .desktop))
                    }
                } else {
                    Label("Правила недоступны. Настройте допуск заново.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if model.needsRuleSetup {
                    AllowedCountrySelectionView()
                }
                Button("Изменить правила…") { showsRules = true }
                    .accessibilityIdentifier("settings-edit-rules")
            }
            .id("access-rules")

            VStack(alignment: .leading, spacing: 6) {
                Text("Приостановка Claude не исключает передачу данных до паузы.")
            }
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            DisclosureGroup("Дополнительно · VPN для всего Mac") {
                PacketGuardView(guardStore: model.packetGuard).padding(.top, 10)
            }
        }
    }

    private var statusColor: Color {
        switch status.tone {
        case .neutral: return .secondary
        case .confirmed: return .primary
        case .attention: return .orange
        case .failure: return .red
        }
    }

    private func protectionStatus(chooseRules: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: status.symbol)
                .font(.system(size: 22))
                .foregroundStyle(statusColor)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(status.title).font(.system(size: 16, weight: .semibold)).foregroundStyle(statusColor)
                    .accessibilityIdentifier("settings-protection-status")
                Text(status.detail).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !model.isSleeping {
                    if model.needsRuleSetup {
                        Button("Настроить допуск", action: chooseRules).buttonStyle(.borderedProminent)
                    } else if !model.protection.isOperational {
                        Button("Проверить подключение") { model.refreshExternalIP() }
                            .disabled(model.externalCheck.isChecking)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
    }

    private var connectionGuidance: String {
        switch model.preferences.vpnLocation {
        case .router: return "Проверяем внешний IP. Локальный туннель не требуется."
        case .thisMac: return "Выберите VPN-приложение ниже."
        case .unspecified: return "Выберите, где подключён ваш VPN."
        }
    }

    private func ruleSummary(_ title: String, rules: AccessRules) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.subheadline.weight(.semibold))
            Text(SettingsRuleSummary.countries(rules))
                .fixedSize(horizontal: false, vertical: true)
            if let restrictions = SettingsRuleSummary.restrictions(rules) {
                Text(restrictions).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var diagnosticsContent: some View {
        // Share the status panel's freshness handling, including an unexpired
        // confirmation during refresh. Raw cached success is not permission.
        let content = StatusPanelContent(model: model)
        return VStack(alignment: .leading, spacing: 22) {
            DiagnosticSummaryView()
            DisclosureGroup("Подробности подключения") {
            VStack(alignment: .leading, spacing: 20) {
            settingsGroup("IP и страна выхода") {
                Text(content.diagnosticsSummary).font(.headline)
                valueRow("Страна", value: content.country)
                valueRow("Внешний IP", value: content.ip)
                Text(content.externalDetail).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if model.usesIndependentConfirmation {
                    valueRow("Источники", value: model.countryComparison?.services ?? "ipwho.is + IPinfo / GeoJS")
                    valueRow("Подтверждение", value: model.recoveryProgress)
                    DisclosureGroup("Как принимается решение") {
                        Text("Восстановление после трёх успешных проверок с интервалом не менее двух секунд. Затем проверка каждые 5 секунд; допуск действует не более 15 секунд от начала проверки. Каждый сервис самостоятельно определяет внешний IP своего запроса; адреса должны совпасть. При лимите или недоступности IPinfo используется GeoJS, с соблюдением паузы сервиса. Страну для разрешения определяет ipwho.is; явный запрет страны из второго ответа сохраняется. Проверяется выход Russian Armor, а не каждого соединения Claude.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 6)
                    }
                } else {
                    Picker("Сервис проверки IP", selection: $model.preferences.egressProvider) {
                        ForEach(EgressProvider.allCases, id: \.self) { provider in
                            Text(provider.title).tag(provider)
                        }
                    }
                    Text("Сервис получает внешний IP проверочного запроса.").foregroundStyle(.secondary)
                }
                Button(model.externalCheck.isChecking ? "Проверяем…" : "Проверить заново") {
                    model.refreshExternalIP()
                }
                .disabled(model.externalCheck.isChecking || model.isSleeping)
                .accessibilityIdentifier("settings-recheck")
            }
            ConnectionDiagnosticsView(monitor: model.connectionDiagnostics,
                                      enabled: $model.preferences.serviceDiagnosticsEnabled,
                                      expectedIP: model.confirmedEgressObservation?.ip)
            ClaudeRoutesView(monitor: model.claudeRoutes, vpnLocation: model.preferences.vpnLocation)
            ProtectionSelfTestView()
            }
            .padding(.top, 12)
            }
            settingsGroup("История событий") {
                Text("Последние \(EventJournal.capacity) событий на этом Mac, без адресов соединений.")
                    .foregroundStyle(.secondary)
                Button("Открыть историю…", action: openHistory)
                    .accessibilityIdentifier("settings-open-history")
            }
        }
    }

    private var generalContent: some View {
        VStack(alignment: .leading, spacing: 22) {
            settingsGroup("Запуск") {
                settingsSwitch("Запускать при входе на Mac", isOn: $model.preferences.startAtLogin)
            }
            settingsGroup("Конфиденциальность") {
                settingsSwitch("Скрывать IP в интерфейсе", isOn: Binding(get: { model.networkEngine.hideIP }, set: { model.networkEngine.setHideIP($0) }))
                settingsSwitch("Записывать изменения сети и туннелей", isOn: $model.preferences.recordNetworkEvents)
                Divider()
                SettingsDetailLink(title: "Хранение данных", detail: "Локальные настройки, история и ключи прокси") { showsPrivacy = true }

            }
            settingsGroup("Обновления") {
                UpdateControls(updater: model.updater)
            }
            settingsGroup("О приложении") {
                Text("Russian Armor").font(.headline)
                if let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
                    valueRow("Версия", value: version)
                }
                valueRow("Автор", value: "danielsuchx")
                Link("GitHub ↗", destination: URL(string: "https://github.com/danielsuchx/russian-armor")!)
                    .help("Открыть репозиторий Russian Armor на GitHub")
            }
        }
    }

    private func settingsGroup<Content: View>(_ title: String, @ViewBuilder content: @escaping () -> Content) -> some View {
        SettingsCard(title: title, content: content)
    }

    private func valueRow(_ title: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(title).foregroundStyle(.secondary)
            Spacer(minLength: 0)
            Text(value).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func settingsSwitch(_ title: String, isOn: Binding<Bool>) -> some View {
        SettingsToggle(title: title, isOn: isOn)
    }
}
