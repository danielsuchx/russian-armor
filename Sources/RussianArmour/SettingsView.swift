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
                    Text("VPN может работать на роутере или на Mac. Внешний IP проверяется только с вашего подтверждения. Файрвол и маршруты не изменяются.")
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

            VStack(alignment: .leading, spacing: 14) {
                Toggle("Показывать имена туннелей при VPN на Mac", isOn: $model.preferences.showInterfaceNames)
                Toggle("Записывать изменения сети и туннелей", isOn: $model.preferences.recordNetworkEvents)
            }
            .toggleStyle(.switch)
            .font(.callout)

            Divider()
            Label {
                Text("Настройки и последние 100 событий — только на этом Mac. Проверка IP — по кнопке, с выбором ipwho.is или Country.is и подтверждением передачи IP выбранному сервису. IP и страна не сохраняются в историю.")
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
