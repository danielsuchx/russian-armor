import ArmorCore
import SwiftUI

/// Fixed width; the panel's height follows its actual content.
enum StatusPanelLayout {
    static let width: CGFloat = 340
    static let cornerRadius: CGFloat = 18
    static let inset: CGFloat = 14
    static let labelWidth: CGFloat = 66
    static let actionHeight: CGFloat = 23

    static func fieldHeight(for value: String) -> CGFloat {
        value.contains("\n") ? 40 : 20
    }
}

enum StatusPanelAction: String, CaseIterable {
    case history, refresh, launchClaude, closeClaude, pause15, pause60, settings, quit
    case readiness, checkIP, failureDetails

    var title: String {
        switch self {
        case .history: return "Вся история…"
        case .refresh: return "Перепроверить"
        case .launchClaude: return "Запустить Claude безопасно"
        case .closeClaude: return "Закрыть Claude…"
        case .pause15: return "Выключить на 15 минут…"
        case .pause60: return "Выключить на 1 час…"
        case .settings: return "Настройки…"
        case .quit: return "Выйти из Russian Armor"
        case .readiness: return "О защите Russian Armor"
        case .checkIP: return "Проверить IP и страну…"
        case .failureDetails: return "Почему проверка IP не удалась?"
        }
    }

    var symbol: String {
        switch self {
        case .history: return "clock.arrow.circlepath"
        case .refresh: return "arrow.clockwise"
        case .launchClaude: return "play"
        case .closeClaude: return "xmark.circle"
        case .pause15, .pause60: return "shield.slash"
        case .settings: return "gearshape"
        case .quit: return "power"
        case .readiness: return "shield.lefthalf.filled"
        case .checkIP: return "globe"
        case .failureDetails: return "exclamationmark.triangle"
        }
    }

    var requiresEnforcement: Bool {
        switch self {
        case .launchClaude, .closeClaude, .pause15, .pause60: return true
        default: return false
        }
    }
}

/// Presentation only. No demo addresses, inferred VPN identity or invented protection.
struct StatusPanelContent: Equatable {
    var country = "Не проверена"
    var vpn: String
    var ip = "Не проверен"
    let ipv6 = "Утечки не проверены"
    var claude: String
    var protection = "Трафик не блокируется\nVPN-маршрут не проверен"
    var ipAction: StatusPanelAction?
    var externalDetail: String
    var diagnosticsSummary: String
    var diagnosticsAction: StatusPanelAction?
    var events: [ActivityEvent]

    @MainActor
    init(model: AppModel) {
        if model.protection != .notConfigured {
            protection = model.protection.title
        }
        vpn = model.preferences.vpnLocation.title
        if model.preferences.vpnLocation == .thisMac, model.preferences.showInterfaceNames,
           let first = model.diagnostics.tunnels.interfaceNames.first {
            let additional = model.diagnostics.tunnels.interfaceNames.count - 1
            vpn = "На Mac · \(first)" + (additional > 0 ? " (+\(additional))" : "")
        }
        claude = model.diagnostics.claudeDesktop.title.lowercased()
        externalDetail = model.automaticChecksEnabled
            ? "\(model.usesIndependentConfirmation ? "Два независимых сервиса" : model.preferences.egressProvider.title) · фоновая проверка \(model.usesIndependentConfirmation ? "каждые 5 секунд" : "раз в минуту")."
            : "Автопроверка выключена. Для разового запроса нажмите на строку IP."
        let confirmedObservation = model.confirmedEgressObservation
        var displayedCheck = model.externalCheck
        if model.externalCheck.isChecking, let confirmedObservation {
            displayedCheck = .observed(confirmedObservation)
        }
        switch displayedCheck {
        case .notChecked, .needsRecheck:
            if model.automaticChecksEnabled {
                country = model.isSleeping ? "Проверка приостановлена" : "Ожидаем сеть"
                ip = country
            } else {
                ipAction = .checkIP
            }
        case .checking:
            country = "Проверяется…"
            ip = "Проверяется…"
        case .observed(let value):
            country = "\(value.countryCode) (\(value.countryName))"
            ip = value.ip
            if let comparison = model.countryComparison {
                let countrySource = comparison.agrees
                    ? "страна подтверждена обоими сервисами"
                    : "геобазы расходятся: \(comparison.detail); для разрешения используется страна по ipwho.is, явный запрет второго ответа сохраняется"
                externalDetail = "IP подтверждён через \(comparison.services); \(countrySource) · \(Self.time(value.checkedAt)). Только запросы Russian Armor, не маршрут других приложений."
            } else {
                externalDetail = "\(value.provider.title) · \(Self.time(value.checkedAt)). Только запрос Russian Armor, не маршрут других приложений."
            }
        case .failed(let message):
            country = "Не определена"
            ip = "Ошибка проверки…"
            ipAction = .failureDetails
            externalDetail = model.usesIndependentConfirmation ? message : "\(model.externalProvider.title): \(message)"
        }
        if model.externalCheck.isChecking, confirmedObservation != nil {
            externalDetail += " Обновляем данные в фоне; прежнее подтверждение ещё действует."
        }
        if let tunnel = model.verifiedTunnel {
            externalDetail += " Проверочный запрос привязан к \(tunnel.interface); владелец \(tunnel.signingID). Это не доказательство выхода каждого соединения Claude."
        }
        if model.isSleeping {
            diagnosticsSummary = "Проверки приостановлены до пробуждения"
        } else if model.externalCheck.isChecking, confirmedObservation == nil {
            diagnosticsSummary = model.processProtection == nil
                ? "Проверяем IP и страну…"
                : "Подтверждаем подключение · Claude на паузе"
        } else if case .failed = model.externalCheck {
            diagnosticsSummary = model.processProtection != nil
                ? "Подключение не подтверждено · Claude на паузе"
                : model.automaticChecksEnabled
                    ? "IP не определён · повторим автоматически"
                    : "IP не определён · подробности…"
            diagnosticsAction = .failureDetails
        } else if model.processProtection != nil, case .needsRecheck = model.externalCheck {
            diagnosticsSummary = "Подключение не подтверждено · Claude на паузе"
        } else if !model.automaticChecksEnabled {
            diagnosticsSummary = "Автопроверка IP выключена · настройки…"
            diagnosticsAction = .settings
        } else if model.protection == .countryConfirmed, confirmedObservation != nil {
            diagnosticsSummary = "Подключение подтверждено"
        } else if case .observed = displayedCheck {
            diagnosticsSummary = "IP и страна обновляются автоматически"
        } else {
            diagnosticsSummary = "Автопроверка IP ожидает доступную сеть"
        }
        events = Array(model.journal.events.prefix(4))
        if model.networkEngine.hideIP {
            ip = EnginePrivacy.display(ip)
            externalDetail = EnginePrivacy.display(externalDetail)
        }
    }

    static func time(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: date)
    }
}

@MainActor
final class StatusPanelPresentation: ObservableObject {
    @Published var showsDiagnostics = false
}

struct StatusPanelView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var presentation: StatusPanelPresentation
    var perform: (StatusPanelAction) -> Void
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var content: StatusPanelContent { StatusPanelContent(model: model) }
    private let primary = Color.white.opacity(0.94)
    private let secondary = Color.white.opacity(0.55)

    var body: some View {
        VStack(spacing: 0) {
            header
            separator
            protectionGuidance
            separator
            fields
            separator
            events
            separator
            actionGroup([.refresh, .launchClaude], padding: 6, showsIcons: false)
            separator
            actionGroup([.readiness, .settings, .quit], padding: 5)
        }
        .padding(.horizontal, StatusPanelLayout.inset)
        .padding(.top, 10)
        .padding(.bottom, 10)
        .frame(width: StatusPanelLayout.width, alignment: .top)
        .fixedSize(horizontal: false, vertical: true)
        .background {
            if reduceTransparency {
                Color(red: 0.11, green: 0.11, blue: 0.11)
            } else {
                StatusPanelMaterial()
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: StatusPanelLayout.cornerRadius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: StatusPanelLayout.cornerRadius, style: .continuous)
                .strokeBorder(Color.white.opacity(0.32), lineWidth: 0.5)
                .padding(0.5)
        }
        .foregroundStyle(primary)
        .font(.system(size: 13))
        .environment(\.colorScheme, .dark)
        // The AppKit window resizes immediately. A separate SwiftUI disclosure
        // animation would render intermediate content inside that final frame.
        .transaction { transaction in
            transaction.animation = nil
            transaction.disablesAnimations = true
        }
        .accessibilityIdentifier("status-panel")
    }

    private var header: some View {
        HStack(spacing: 6) {
            Image(systemName: model.protection.symbol)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(model.protection.isOperational ? .green : .orange)
                .frame(width: 18)
                .accessibilityHidden(true)
            Button { perform(.readiness) } label: {
                Text(model.protection.title)
                    .font(.system(size: 14, weight: .bold))
                    .lineLimit(2)
            }
            .buttonStyle(.plain)
            .help(model.protection.detail)
            Spacer(minLength: 4)
        }
        .frame(height: 38)
        .padding(.bottom, 8)
    }

    private var fields: some View {
        VStack(spacing: 0) {
            field("Страна", value: content.country, help: content.externalDetail)
            field("IP", value: content.ip, help: content.externalDetail, action: content.ipAction)

            Button {
                presentation.showsDiagnostics.toggle()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: presentation.showsDiagnostics ? "chevron.down" : "chevron.right")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(secondary)
                        .frame(width: 18)
                        .accessibilityHidden(true)
                    Text("Информация о подключении")
                    Spacer(minLength: 0)
                }
                .frame(height: StatusPanelLayout.actionHeight)
                .contentShape(Rectangle())
            }
            .buttonStyle(StatusPanelButtonStyle())
            .accessibilityValue(presentation.showsDiagnostics ? "Развернуто" : "Свернуто")
            .accessibilityIdentifier("status-diagnostics-disclosure")

            if presentation.showsDiagnostics {
                VStack(spacing: 0) {
                    field("VPN", value: content.vpn, help: "Расположение указано в настройках. Имя интерфейса не доказывает маршрут VPN.")
                    field("IPv6", value: content.ipv6, help: "Отсутствие IPv6-утечек пока не проверяется.")
                    field("Claude", value: content.claude, help: "Только наличие Claude Desktop. Сессии Code не подсчитываются.")
                    field("Маршрут", value: model.claudeRoutes.state.title,
                          help: "Сокеты Desktop и Code и маршруты ОС к их узлам. Подробности — в настройках. Выход после прокси или роутера не подтверждён.")
                    field(
                        "Защита",
                        value: content.protection,
                        height: StatusPanelLayout.fieldHeight(for: content.protection),
                        help: model.protection.detail
                    )
                }
                .padding(.top, 6)
            }
        }
        .padding(.vertical, 8)
    }

    private var protectionGuidance: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !model.watchdogHealthy {
                Label("Восстановление защиты недоступно · Claude на паузе", systemImage: "exclamationmark.triangle")
                    .font(AppTypography.description)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(model.protection.detail)
                .font(AppTypography.description)
                .foregroundStyle(secondary)
                .fixedSize(horizontal: false, vertical: true)
            Group {
                if let action = content.diagnosticsAction {
                    Button(content.diagnosticsSummary) { perform(action) }
                        .buttonStyle(.plain)
                        .foregroundStyle(Color.accentColor)
                } else {
                    Text(content.diagnosticsSummary)
                }
            }
            .font(AppTypography.description)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("status-diagnostics-summary")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 10)
    }

    private func field(_ label: String, value: String, height: CGFloat = 20,
                       help: String, action: StatusPanelAction? = nil) -> some View {
        HStack(alignment: .top, spacing: 0) {
            Text(label)
                .foregroundStyle(secondary)
                .frame(width: StatusPanelLayout.labelWidth, alignment: .leading)
            Group {
                if let action {
                    Button(value) { perform(action) }
                        .buttonStyle(.plain)
                        .foregroundStyle(action == .failureDetails ? Color.orange : primary)
                } else {
                    Text(value)
                }
            }
            .lineLimit(height > 20 ? 2 : 1)
            .frame(maxWidth: .infinity, alignment: .leading)
            .monospacedDigit()
        }
        .frame(height: height, alignment: .top)
        .help(help)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("status-field-\(label)")
    }

    private var events: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(model.recentEventsTitle)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(secondary)
                .frame(height: 16, alignment: .leading)
                .padding(.bottom, 3)
            if content.events.isEmpty {
                Text("Пока нет событий")
                    .foregroundStyle(secondary)
                    .frame(height: 19.5)
            }
            ForEach(content.events) { event in
                HStack(spacing: 6) {
                    Circle()
                        .fill(model.journal.isUnread(event) ? Color.blue : Color.clear)
                        .frame(width: 5, height: 5)
                        .accessibilityHidden(true)
                    Image(systemName: event.kind.symbol)
                        .foregroundStyle(secondary)
                        .frame(width: 18)
                        .accessibilityHidden(true)
                    Text(event.title)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text(StatusPanelContent.time(event.date))
                        .font(.system(size: 10.5, weight: .medium))
                        .monospacedDigit()
                        .foregroundStyle(secondary)
                }
                .frame(height: 19.5)
                .help(event.detail)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(model.journal.isUnread(event) ? "Новое событие. " : "")\(event.title). \(StatusPanelContent.time(event.date))")
            }
            actionGroup([.history], padding: 0, showsIcons: false)
                .frame(height: 24)
                .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 9)
        .padding(.bottom, 2.5)
    }

    private var separator: some View {
        Rectangle().fill(Color.white.opacity(0.12)).frame(height: 0.5)
    }

    private func actionGroup(_ actions: [StatusPanelAction], padding: CGFloat, showsIcons: Bool = true) -> some View {
        VStack(spacing: 0) {
            ForEach(actions, id: \.self) { action in
                Button { perform(action) } label: {
                    HStack(spacing: 6) {
                        if showsIcons {
                            Image(systemName: action.symbol)
                                .foregroundStyle(secondary)
                                .frame(width: 18)
                                .accessibilityHidden(true)
                        }
                        Text(action.title)
                        Spacer(minLength: 0)
                    }
                    .frame(height: StatusPanelLayout.actionHeight)
                    .contentShape(Rectangle())
                }
                .buttonStyle(StatusPanelButtonStyle())
                .disabled(actionIsDisabled(action))
                .help(actionHelp(action))
                .accessibilityIdentifier("status-action-\(action.rawValue)")
            }
        }
        .padding(.vertical, padding)
    }

    private func actionIsDisabled(_ action: StatusPanelAction) -> Bool {
        if action == .launchClaude { return !model.canLaunchClaudeUnderProtection }
        return action.requiresEnforcement || (action == .refresh && model.isSleeping)
    }

    private func actionHelp(_ action: StatusPanelAction) -> String {
        if action == .launchClaude {
            return model.canLaunchClaudeUnderProtection
                ? "Запустить Claude при свежем подтверждении разрешённой страны. Контроль работает на уровне процесса, не как сетевой kill switch."
                : "Недоступно: дождитесь свежего подтверждения разрешённой страны и убедитесь, что Claude установлен и закрыт."
        }
        if action.requiresEnforcement {
            return "Недоступно: это управление Claude ещё не реализовано."
        }
        return action == .refresh
            ? "Обновить диагностику. Автопроверка IP продолжится, если включена."
            : action.title
    }
}

private struct StatusPanelButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(isEnabled ? 1 : 0.38)
            .background {
                if isEnabled && (hovering || configuration.isPressed) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.accentColor.opacity(configuration.isPressed ? 0.8 : 1))
                        .padding(.horizontal, -5)
                }
            }
            .onHover { hovering = $0 }
    }
}
