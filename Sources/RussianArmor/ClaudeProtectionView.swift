import SwiftUI

struct ClaudeProtectionView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var filter: ClaudeNetworkFilterStore
    @State private var launchError: String?

    var body: some View {
        SettingsCard(title: "Только Claude · Desktop, Code и отдельный браузер") {
            Text("Контроль процессов Claude работает без строгого режима. Остальные приложения используют свои маршруты; при Xkeen трафик продолжает направлять роутер.")
                .foregroundStyle(.secondary)
            Divider()
            Label("Браузер Claude · ограничение WebRTC по умолчанию", systemImage: "globe.badge.shield.checkmark")
                .fontWeight(.medium)
            Text("Отдельный профиль Chrome, Brave, Chromium или Edge. Прямой WebRTC/UDP и QUIC запрещены, DNS включён через DoH без обычного DNS-fallback. Обычные профили, в том числе для российских сайтов, не меняются.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Cloudflare видит DNS-запросы; DoH скрывает их от локального DNS-провайдера. Маршрут DoH определяется VPN/Xkeen.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Открыть Claude в отдельном браузере") {
                launchError = nil
                Task { do { try await model.launchClaudeBrowser() } catch { launchError = error.localizedDescription } }
            }
            .disabled(!model.canLaunchClaudeBrowser)
            .accessibilityIdentifier("claude-browser-launch")
            if !model.canLaunchClaudeBrowser {
                Text("Открытие доступно после подтверждения разрешённой страны и готовности контроля Claude.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Divider()
            Label(
                filter.verified
                    ? "WebRTC Desktop · UDP блокируется фильтром macOS"
                    : (filter.bundled ? "WebRTC Desktop · ждём разрешение macOS" : "WebRTC Desktop · политики запуска готовы"),
                systemImage: filter.verified ? "checkmark.shield" : "shield.lefthalf.filled"
            )
                .foregroundStyle(filter.verified ? Color.primary : Color.orange)
            Text("Фильтр блокирует UDP у Claude и его helpers, а при потере разрешения — их TCP-соединения. Общий VPN и изменение DNS не требуются. На голосовые функции Claude это может повлиять.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Запуск Claude кнопкой Russian Armor передаёт Electron политики WebRTC и secure DoH. Уже открытый или вручную запущенный Claude нужно закрыть и запустить заново через Russian Armor.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Фильтр ограничивает соединения, но не выбирает их маршрут. Для выхода всех соединений Claude через VPN нужна отдельная настройка маршрутизации.")
                .font(.caption).foregroundStyle(.secondary)
            if !filter.verified {
                if filter.bundled {
                    Button(filter.waitingForApproval ? "Открыть разрешения macOS" : "Разрешить фильтр Claude…") {
                        if filter.waitingForApproval {
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
                        } else { filter.activate() }
                    }.disabled(filter.busy)
                } else {
                    Text("Системный фильтр macOS требует платной подписи Apple и не используется. Бесплатный режим применяет политики при запуске Claude через Russian Armor; строгую защиту всего Mac включать не нужно.")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            if let error = filter.error ?? launchError { Text(error).font(.caption).foregroundStyle(.orange) }
        }
    }
}
