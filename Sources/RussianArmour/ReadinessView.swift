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

                if model.preferences.allowedCountryCode == nil {
                    AllowedCountrySelectionView()
                }

                explanation(
                    title: "Проверяет IP и страну",
                    detail: "При запуске, смене сети и раз в минуту. Плановая проверка идёт в фоне; Claude ставится на паузу при смене сети, ошибке или несовпадении страны.",
                    symbol: "globe",
                    color: .secondary
                )
            }

            Text("Защита работает на уровне процессов. Между изменением сети и паузой возможен короткий промежуток; для строгой блокировки включите также kill switch VPN.")
                .font(.caption)
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
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
