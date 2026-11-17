import SwiftUI

struct ReadinessView: View {
    @EnvironmentObject private var model: AppModel
    var openSettings: () -> Void
    var close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Защита Claude")
                .font(.title2.weight(.semibold))

            VStack(alignment: .leading, spacing: 18) {
                explanation(title: model.protection.title, detail: model.protection.detail,
                            symbol: model.protection.symbol,
                            color: model.protection.isOperational ? .green : .orange)

                if model.needsRuleSetup {
                    AllowedCountrySelectionView()
                }

                explanation(
                    title: model.claudeRoutes.state.title,
                    detail: "Фоновый снимок сокетов Claude Desktop и Code и маршрутов ОС к их узлам. При VPN на Mac внешний источник или маршрут вне туннеля ставит Claude на паузу. Подробности — в настройках. Выход после прокси или роутера не подтверждается.",
                    symbol: "point.3.connected.trianglepath.dotted",
                    color: .secondary
                )

                explanation(
                    title: "Проверяет IP и страну",
                    detail: "При запуске и изменении сети допуск закрыт. Для восстановления нужны три успешные проверки с интервалом не менее двух секунд. В режиме VPN на Mac запрос привязан к подтверждённому туннелю; геобаза проверяет тот же IP. Разрешения и запреты настраиваются в профилях.",
                    symbol: "globe",
                    color: .secondary
                )
            }

            if !model.watchdogHealthy {
                Label("Наблюдатель восстановления недоступен. Claude остаётся на паузе.", systemImage: "exclamationmark.triangle")
                    .font(AppTypography.description)
                    .foregroundStyle(.orange)
            }

            Text("Защита работает на уровне процессов. Между изменением сети и паузой возможен короткий промежуток; для строгой блокировки включите также kill switch VPN.")
                .font(AppTypography.description)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Button("Настройки…", action: openSettings)
                    .accessibilityIdentifier("readiness-settings")
                Spacer()
                Button("Понятно", action: close)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("readiness-close")
            }
        }
        .padding(24)
        .frame(width: 460)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func explanation(title: String, detail: String, symbol: String, color: Color) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 20))
                .foregroundStyle(color)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(title)
                    .font(.headline)
                Text(detail)
                    .font(AppTypography.description)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
