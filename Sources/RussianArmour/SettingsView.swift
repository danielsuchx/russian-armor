import ArmourCore
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            settingsContent
                .padding(24)
        }
        .frame(width: 480)
    }

    private var settingsContent: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 32))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Russian Armour")
                        .font(.title2.weight(.semibold))
                    Text("Claude Desktop и Claude Code")
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
                    Text("Russian Armour ставит Claude Desktop, Claude Code и их дочерние процессы на паузу, пока страна выхода не подтверждена.")
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
                HStack {
                    Text("Разрешённая страна VPN")
                    Spacer()
                    Text(model.preferences.allowedCountryCode ?? "Не выбрана")
                        .foregroundStyle(model.preferences.allowedCountryCode == nil ? .orange : .secondary)
                }
                if model.preferences.allowedCountryCode != nil {
                    Button("Выбрать заново") { model.clearAllowedCountry() }
                } else {
                    AllowedCountrySelectionView()
                }
                if model.usesIndependentConfirmation {
                    HStack {
                        Text("Проверка IP")
                        Spacer()
                        Text("ipwho.is + IPinfo")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Picker("Сервис проверки IP", selection: $model.preferences.egressProvider) {
                        ForEach(EgressProvider.allCases, id: \.self) { provider in
                            Text(provider.title).tag(provider)
                        }
                    }
                }
                Text(model.usesIndependentConfirmation
                     ? "При запуске, изменении сети и пробуждении, затем раз в минуту. Защита включается, только если оба сервиса видят один IP и страну."
                     : "Разовая диагностика через \(model.preferences.egressProvider.host). Сервис получает внешний IP запроса.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 14) {
                Toggle("Показывать имена туннелей при VPN на Mac", isOn: $model.preferences.showInterfaceNames)
                Toggle("Записывать изменения сети и туннелей", isOn: $model.preferences.recordNetworkEvents)
                Toggle("Запустить Russian Armour при входе на Mac", isOn: $model.preferences.startAtLogin)
            }
            .toggleStyle(.switch)
            .font(.callout)

            Divider()
            Label {
                Text("Настройки и последние 100 событий — только на этом Mac. Сохраняется код разрешённой страны; IP остаётся в памяти и не записывается в историю.")
            } icon: {
                Image(systemName: "internaldrive")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}
