import ArmourCore
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 32))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Russian Armour")
                        .font(.title2.weight(.semibold))
                    Text("Версия 0.2.0 · диагностика подключения")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Label(model.protection.title, systemImage: model.protection.symbol)
                        .font(.headline)
                        .foregroundStyle(.orange)
                    Text(model.protection.detail)
                        .font(.callout)
                    Text("VPN может работать на роутере или на Mac. Проверка внешнего IP не подтверждает маршрут других приложений. Файрвол и маршруты не изменяются.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }

            VStack(alignment: .leading, spacing: 8) {
                Picker("Где работает VPN", selection: $model.preferences.vpnLocation) {
                    ForEach(VPNLocation.allCases, id: \.self) { location in
                        Text(location.title).tag(location)
                    }
                }
                Text("Это ваше указание, не результат проверки. Для VPN на роутере локальный туннель не требуется.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 8) {
                Toggle("Определять IP и страну автоматически", isOn: $model.preferences.automaticIPChecks)
                    .toggleStyle(.switch)
                Picker("Сервис проверки IP", selection: $model.preferences.egressProvider) {
                    ForEach(EgressProvider.allCases, id: \.self) { provider in
                        Text(provider.title).tag(provider)
                    }
                }
                Text("При запуске, изменении сети и пробуждении, затем примерно раз в минуту. \(model.preferences.egressProvider.host) получает внешний IP запроса. При ошибке повторяется запрос к тому же сервису — без переключения на другой.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 14) {
                Toggle("Показывать имена туннелей при VPN на Mac", isOn: $model.preferences.showInterfaceNames)
                Toggle("Записывать изменения сети и туннелей", isOn: $model.preferences.recordNetworkEvents)
            }
            .toggleStyle(.switch)
            .font(.callout)

            Divider()
            Label {
                Text("Настройки и последние 100 событий — только на этом Mac. IP и страна остаются в памяти и не сохраняются в историю. Если отключить автопроверку, запросы выполняются только по кнопке с выбором сервиса.")
            } icon: {
                Image(systemName: "internaldrive")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(width: 480)
    }
}
