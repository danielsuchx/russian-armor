import ArmourCore
import SwiftUI

struct ReadinessView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label("Что нужно для защиты", systemImage: "shield.lefthalf.filled")
                .font(.title2.weight(.semibold))
            Text("Сейчас работает диагностика. Включить блокировку трафика в этой версии нельзя — это не ошибка настройки и не отсутствие разрешений.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 18) {
                step(
                    symbol: "network",
                    title: "Локальная диагностика",
                    status: model.diagnostics.checkedAt == nil ? "Ожидает проверки" : "Доступна",
                    detail: "Показывает доступность сети, интерфейсы utun и состояние Claude Desktop. Не подтверждает маршрут трафика."
                )
                Divider()
                step(
                    symbol: "point.topleft.down.to.point.bottomright.curvepath",
                    title: "Проверка внешнего выхода",
                    status: model.preferences.automaticIPChecks ? "Автоматически · \(model.preferences.egressProvider.title)" : "По кнопке · автопроверка выключена",
                    detail: "Работает и с VPN на роутере. Выбранный сервис (ipwho.is или Country.is) возвращает IP и оценку страны запроса Russian Armour. Это не подтверждает маршрут Claude, всех соединений Mac или сам факт VPN."
                )
                Divider()
                step(
                    symbol: "shield.slash",
                    title: "Сетевая блокировка",
                    status: "Ещё не реализована",
                    detail: "Нужен отдельный механизм macOS, проверенный при отключении VPN, смене сети, сне и сбое приложения."
                )
            }
            .padding(16)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))

            Label("Безопасный запуск и пауза появятся после реализации и проверки защиты.", systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(width: 510)
    }

    private func step(symbol: String, title: String, status: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 18))
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.headline)
                Text(status)
                    .font(.caption.weight(.medium))
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
