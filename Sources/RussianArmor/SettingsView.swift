import ArmorCore
import SwiftUI

enum SettingsLayout {
    static let defaultSize = NSSize(width: 820, height: 720)
    static let minimumSize = NSSize(width: 760, height: 620)
    static let sidebarWidth: CGFloat = 176
}

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: SettingsSection?
    @State private var showsRules = false
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
                VStack(alignment: .leading, spacing: 6) {
                    Text(section.title).font(.title.weight(.semibold))
                        .accessibilityAddTraits(.isHeader)
                    Text(section.subtitle).foregroundStyle(.secondary)
                }
                .padding(24)
                Divider()
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
        .frame(minWidth: SettingsLayout.minimumSize.width, minHeight: SettingsLayout.minimumSize.height)
        .sheet(isPresented: $showsRules) {
            AccessRulesEditor(configuration: model.accessConfiguration).environmentObject(model)
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
                    }
                }
                .font(AppTypography.description)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(24)
            }
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            List(selection: $selection) {
                ForEach(SettingsSection.allCases) { section in
                    Label(section.title, systemImage: section.symbol)
                        .padding(.vertical, 5)
                        .tag(section)
                        .accessibilityIdentifier("settings-section-\(section.rawValue)")
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
                Label("Граница защиты", systemImage: "info.circle").font(.subheadline.weight(.semibold))
                Text("Контроль приостанавливает процессы Claude, но не блокирует трафик до паузы. Данные могут успеть уйти; отсутствие сетевых утечек не гарантируется.")
            }
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
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
                .font(.system(size: 26))
                .foregroundStyle(statusColor)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 8) {
                Text(status.title).font(.title2.weight(.semibold)).foregroundStyle(statusColor)
                    .accessibilityIdentifier("settings-protection-status")
                Text(status.detail).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !model.isSleeping {
                    if model.needsRuleSetup {
                        Button("Настроить допуск", action: chooseRules)
                    } else if !model.protection.isOperational {
                        Button("Проверить подключение") { model.refreshExternalIP() }
                            .disabled(model.externalCheck.isChecking)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
    }

    private var connectionGuidance: String {
        switch model.preferences.vpnLocation {
        case .router: return "Вы указали VPN на роутере. Локальный туннель не требуется; выход за роутером напрямую не виден."
        case .thisMac: return "Вы указали VPN на этом Mac. Выберите владельца локального туннеля ниже."
        case .unspecified: return "Укажите, где работает VPN. Сам выбор не подтверждает подключение."
        }
    }

    private func ruleSummary(_ title: String, rules: AccessRules) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.subheadline.weight(.semibold))
            Text("Разрешённые страны: \(SettingsRuleSummary.countries(rules))")
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
                        Text("Восстановление после трёх успешных проверок с интервалом не менее двух секунд. Затем проверка каждые 5 секунд; допуск действует не более 15 секунд от начала проверки. Каждый сервис самостоятельно определяет внешний IP своего запроса; адреса должны совпасть. При лимите или недоступности IPinfo используется GeoJS, с соблюдением паузы сервиса. В режиме одной страны источник правила — ipwho.is; в правилах профиля учитываются оба ответа. Проверяется выход Russian Armor, а не каждого соединения Claude.")
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
            settingsGroup("История событий") {
                Text("До \(EventJournal.capacity) последних событий на этом Mac. Наблюдаемые IP и адреса соединений не записываются в историю.")
                    .foregroundStyle(.secondary)
                Button("Открыть историю…", action: openHistory)
                    .accessibilityIdentifier("settings-open-history")
            }
        }
    }

    private var generalContent: some View {
        VStack(alignment: .leading, spacing: 22) {
            settingsGroup("Запуск") {
                settingsSwitch("Запускать Russian Armor при входе на Mac", isOn: $model.preferences.startAtLogin)
            }
            settingsGroup("События и данные") {
                settingsSwitch("Записывать изменения сети и туннелей", isOn: $model.preferences.recordNetworkEvents)
                Divider()
                Label {
                    Text("Настройки и последние \(EventJournal.capacity) событий хранятся только на этом Mac. Наблюдаемые IP и адреса соединений остаются в памяти и не записываются в историю. IP и диапазоны, введённые в правила допуска, сохраняются локально как настройки.")
                } icon: {
                    Image(systemName: "internaldrive")
                }
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
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

    private func settingsGroup<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12, content: content)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
        } label: {
            Text(title).font(.headline).accessibilityAddTraits(.isHeader)
        }
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
        Toggle(isOn: isOn) {
            Text(title).fixedSize(horizontal: false, vertical: true)
        }
        .toggleStyle(.switch)
    }
}
