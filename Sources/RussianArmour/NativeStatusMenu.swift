import AppKit
import ArmourCore
import Combine

@MainActor
final class NativeStatusMenu: NSObject, NSMenuDelegate {
    enum WindowKind: Hashable { case settings, history, readiness, traffic }
    private static let statusBarSymbolSize: CGFloat = 18

    let menu = NSMenu()
    private let model: AppModel
    private let openWindow: (WindowKind) -> Void
    private var statusItem: NSStatusItem?
    private var subscription: AnyCancellable?
    private var fields: [String: NSMenuItem] = [:]
    private var eventItems: [NSMenuItem] = []
    private var checkIPItem: NSMenuItem!
    private var refreshItem: NSMenuItem!
    private var noteItem: NSMenuItem!
    private(set) lazy var panel = StatusPanelController(model: model) { [weak self] action in
        self?.performPanelAction(action)
    }

    init(model: AppModel, createStatusItem: Bool = true, openWindow: @escaping (WindowKind) -> Void) {
        self.model = model
        self.openWindow = openWindow
        super.init()
        menu.autoenablesItems = false
        menu.font = .menuFont(ofSize: 13)
        menu.minimumWidth = 300
        menu.delegate = self
        buildMenu()
        if createStatusItem {
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
            item.button?.image = symbol(model.protection.symbol, size: Self.statusBarSymbolSize)
            item.button?.imagePosition = .imageOnly
            item.button?.setAccessibilityLabel("Russian Armour — \(model.protection.title.lowercased())")
            item.button?.toolTip = "Russian Armour · правый клик — все действия диагностики"
            item.button?.target = self
            item.button?.action = #selector(togglePanel(_:))
            item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
            statusItem = item
        }
        subscription = Publishers.Merge(model.objectWillChange, model.traffic.objectWillChange)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.updateContents() }
        updateContents()
    }

    private func buildMenu() {
        let heading = information(model.protection.title)
        heading.image = symbol(model.protection.symbol, size: 12)
        heading.toolTip = model.protection.detail
        menu.addItem(.separator())
        for (name, icon) in [
            ("Страна", "globe.europe.africa"),
            ("VPN", "network"),
            ("IP", "number"),
            ("IPv6", "arrow.left.arrow.right"),
            ("Claude", "app"),
            ("Защита", model.protection.symbol)
        ] {
            fields[name] = information(name, symbol: icon)
        }
        fields["Соединения"] = information("Соединения", symbol: "arrow.up.arrow.down")
        noteItem = information("Автопроверка IP включена")
        noteItem.toolTip = "Проверка внешнего выхода не доказывает защиту трафика Claude, браузера или всех соединений Mac. Для VPN на роутере локальный туннель не требуется."
        menu.addItem(.separator())
        information("Последние события")
        for _ in 0..<4 { eventItems.append(information("")) }
        action("Вся история…", symbol: "clock.arrow.circlepath", selector: #selector(showHistory))
        menu.addItem(.separator())
        refreshItem = action("Перепроверить", symbol: "arrow.clockwise", selector: #selector(refresh))
        refreshItem.toolTip = "Локальная диагностика и сброс результата IP. Если включена автопроверка, внешний IP обновится автоматически после проверки сети."
        checkIPItem = action("Проверить IP и страну…", symbol: "globe", selector: #selector(confirmExternalCheck))
        action("Сетевые соединения…", symbol: "arrow.up.arrow.down", selector: #selector(showTraffic))
        action(StatusPanelAction.readiness.title, symbol: "shield.lefthalf.filled", selector: #selector(showReadiness))
        menu.addItem(.separator())
        action("Настройки…", symbol: "gearshape", selector: #selector(showSettings), key: ",")
        action("Выйти из Russian Armour", symbol: "power", selector: #selector(quit), key: "q")
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        model.expireExternalCheck()
        model.refreshDiagnostics()
        updateContents()
    }

    /// Update existing native menu items, preserving tracking and keyboard selection.
    func updateContents() {
        menu.items.first?.title = model.protection.title
        menu.items.first?.image = symbol(model.protection.symbol, size: 12)
        menu.items.first?.toolTip = model.protection.detail
        statusItem?.button?.image = symbol(model.protection.symbol, size: Self.statusBarSymbolSize)
        statusItem?.button?.setAccessibilityLabel("Russian Armour — \(model.protection.title.lowercased())")
        statusItem?.button?.toolTip = "Russian Armour — \(model.protection.title.lowercased()). Правый клик — все действия диагностики."
        var country = "Не проверена"
        var ip = "Не проверен"
        noteItem.toolTip = "Проверка внешнего выхода не доказывает защиту трафика Claude, браузера или всех соединений Mac. Для VPN на роутере локальный туннель не требуется."
        noteItem.action = nil
        noteItem.target = nil
        noteItem.isEnabled = false
        noteItem.image = nil
        switch model.externalCheck {
        case .notChecked:
            if model.automaticChecksEnabled {
                noteItem.title = model.isSleeping ? "Автопроверка IP приостановлена" : "Автопроверка IP: ожидаем сеть"
                noteItem.toolTip = "Автоматический запрос к \(model.preferences.egressProvider.host) после подключения к сети. Отключить можно в настройках."
            } else {
                noteItem.title = "Автопроверка IP выключена"
            }
        case .checking:
            country = "Проверяется…"
            ip = "Проверяется…"
            noteItem.title = "Запрос к \(model.externalProvider.title)…"
        case .observed(let value):
            country = "\(value.countryCode) (\(value.countryName))"
            ip = value.ip
            noteItem.title = model.automaticChecksEnabled
                ? "\(model.usesIndependentConfirmation ? "2 сервиса" : value.provider.title) · автообновление IP"
                : "\(value.provider.title) · только запрос проверки"
        case .failed(let message):
            country = "Ошибка проверки"
            ip = "Ошибка проверки"
            noteItem.title = "Проверка IP не удалась — подробнее…"
            noteItem.toolTip = "\(model.externalProvider.title): \(message)"
            noteItem.image = symbol("exclamationmark.triangle")
            noteItem.action = #selector(showExternalFailure)
            noteItem.target = self
            noteItem.isEnabled = true
        case .needsRecheck(let message):
            noteItem.title = model.automaticChecksEnabled
                ? (model.isSleeping ? "Автопроверка IP приостановлена" : "Автопроверка IP: ожидаем сеть")
                : "Результат сброшен — повторите проверку"
            noteItem.toolTip = message
        }
        fields["Страна"]?.title = "Страна: \(country)"
        fields["VPN"]?.title = "VPN: \(model.preferences.vpnLocation.title)"
        fields["VPN"]?.toolTip = vpnExplanation
        fields["IP"]?.title = "IP: \(ip)"
        fields["IPv6"]?.title = "IPv6: утечки не проверены"
        fields["Claude"]?.title = "Claude: \(model.diagnostics.claudeDesktop.title.lowercased())"
        fields["Claude"]?.toolTip = "Защита охватывает Claude Desktop, распознанный Claude Code и их дочерние процессы текущего пользователя."
        fields["Защита"]?.title = model.protection == .notConfigured
            ? "Защита: трафик не блокируется" : "Защита: \(model.protection.title.lowercased())"
        fields["Защита"]?.toolTip = model.protection.detail
        fields["Соединения"]?.title = "Соединения: \(model.traffic.state.title)"
        fields["Соединения"]?.toolTip = "Только сокеты текущего пользователя. Не полный журнал пакетов и не проверка VPN-маршрута."
        let events = model.journal.events
        for (index, item) in eventItems.enumerated() {
            if index < events.count {
                let event = events[index]
                item.title = event.title
                item.image = symbol(event.kind.symbol)
                item.toolTip = "\(event.date.formatted(date: .abbreviated, time: .shortened)) · \(event.detail)"
                item.isHidden = false
            } else {
                item.title = "Пока нет событий"
                item.image = symbol("clock")
                item.isHidden = index != 0
            }
        }
        refreshItem.isEnabled = !model.isSleeping
        checkIPItem.isEnabled = !model.externalCheck.isChecking && !model.isSleeping
        checkIPItem.title = model.externalCheck.isChecking ? "Проверяем IP и страну…"
            : (model.automaticChecksEnabled ? "Обновить IP и страну" : "Проверить IP и страну…")
    }

    private var vpnExplanation: String {
        if model.preferences.vpnLocation == .router {
            return "Указано вами. Безопасность определяется свежей проверкой разрешённой страны выхода."
        }
        if model.preferences.vpnLocation == .thisMac {
            let names = model.diagnostics.tunnels.interfaceNames
            let detail = model.preferences.showInterfaceNames && !names.isEmpty
                ? names.joined(separator: ", ") : model.diagnostics.tunnels.title
            return "Указано вами. Локальные туннели: \(detail). Их наличие не доказывает VPN-маршрут."
        }
        return "Укажите расположение VPN в настройках. Оно не определяется по наличию VPN-приложения."
    }

    @discardableResult
    private func information(_ title: String, symbol name: String? = nil) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.image = name.flatMap { symbol($0) }
        item.isEnabled = false
        menu.addItem(item)
        return item
    }

    @discardableResult
    private func action(_ title: String, symbol name: String, selector: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        item.image = symbol(name)
        item.isEnabled = true
        menu.addItem(item)
        return item
    }

    private func symbol(_ name: String, size: CGFloat = 14) -> NSImage? {
        guard let source = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(.init(pointSize: size, weight: .medium)) else { return nil }
        let scale = size / max(source.size.width, source.size.height)
        let fittedSize = NSSize(width: source.size.width * scale, height: source.size.height * scale)
        // On macOS 27.0.1, NSMenu omits symbol-backed images even when they draw
        // correctly elsewhere. A drawing-backed template keeps the SF Symbol,
        // Retina rendering and native disabled/highlight colors without custom rows.
        let image = NSImage(size: fittedSize, flipped: false) { rect in
            source.draw(in: rect)
            return true
        }
        image.isTemplate = true
        return image
    }

    @objc private func togglePanel(_ sender: NSStatusBarButton) {
        if NSApp.currentEvent?.type == .rightMouseUp {
            panel.close()
            menu.popUp(positioning: nil, at: NSPoint(x: 0, y: sender.bounds.minY), in: sender)
        } else {
            model.refreshDiagnostics()
            panel.toggle(relativeTo: sender)
        }
    }

    func performPanelAction(_ action: StatusPanelAction) {
        // Also enforce disabled actions at the controller boundary, not just visually.
        guard !action.requiresEnforcement else { return }
        panel.close()
        switch action {
        case .history: showHistory()
        case .refresh: refresh()
        case .settings: showSettings()
        case .quit: quit()
        case .readiness: showReadiness()
        case .checkIP: confirmExternalCheck()
        case .failureDetails: showExternalFailure()
        case .launchClaude, .closeClaude, .pause15, .pause60: break
        }
    }

    @objc private func refresh() { model.refresh() }
    @objc private func showHistory() { openWindow(.history) }
    @objc private func showTraffic() { openWindow(.traffic) }
    @objc private func showReadiness() { openWindow(.readiness) }
    @objc private func showSettings() { openWindow(.settings) }
    @objc private func quit() { NSApp.terminate(nil) }

    @objc private func confirmExternalCheck() {
        guard !model.externalCheck.isChecking, !model.isSleeping else { return }
        if model.automaticChecksEnabled {
            model.refreshExternalIP()
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        let alert = Self.externalCheckConsentAlert()
        let response = alert.runModal()
        if let provider = Self.confirmedProvider(for: response) {
            model.checkExternalIPAfterConsent(provider: provider)
        }
    }

    static func externalCheckConsentAlert() -> NSAlert {
        let alert = NSAlert()
        alert.messageText = "Через какой сервис проверить IP?"
        alert.informativeText = "Будет отправлен один HTTPS-запрос только к выбранному сервису: ipwho.is или ipinfo.io. Он увидит IP запроса и вернёт адрес и оценку страны. Это не проверка маршрута Claude или всех соединений Mac. IP и страна не сохраняются в историю. Автоматических повторов и переключения между сервисами нет."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Через ipwho.is")
        alert.addButton(withTitle: "Через IPinfo")
        alert.addButton(withTitle: "Отмена").keyEquivalent = "\u{1b}"
        return alert
    }

    static func confirmedProvider(for response: NSApplication.ModalResponse) -> EgressProvider? {
        switch response {
        case .alertFirstButtonReturn: return .ipWhoIS
        case .alertSecondButtonReturn: return .ipInfo
        default: return nil
        }
    }

    @objc private func showExternalFailure() {
        guard let alert = externalFailureAlert() else { return }
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    func externalFailureAlert() -> NSAlert? {
        guard case .failed(let message) = model.externalCheck else { return nil }
        let alert = NSAlert()
        alert.messageText = "Не удалось определить внешний IP"
        let nextStep = model.automaticChecksEnabled
            ? "IP и страна неизвестны. При доступной сети автопроверка повторится примерно через минуту\(model.usesIndependentConfirmation ? " через два независимых сервиса." : " через \(model.preferences.egressProvider.title). Для смены сервиса откройте настройки.")"
            : "IP и страна неизвестны. Можно повторить проверку через другой сервис: закройте это окно и нажмите «Проверить IP и страну…». Новый запрос выполняется только после выбора сервиса."
        alert.informativeText = "\(model.externalProvider.title): \(message)\n\n\(nextStep)"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Закрыть")
        return alert
    }
}
