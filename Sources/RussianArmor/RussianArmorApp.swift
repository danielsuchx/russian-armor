import AppKit
import Darwin
import SwiftUI
import ServiceManagement

@main
struct RussianArmorApp {
    @MainActor
    static func main() {
        if ApplicationWatchdog.runHelperIfRequested() { return }
        let app = NSApplication.shared
        if let icon = AppIcon.image {
            app.applicationIconImage = icon
        }
        guard getuid() != 0, geteuid() == getuid() else {
            let alert = NSAlert()
            alert.messageText = "Запустите Russian Armor без sudo"
            alert.informativeText = "Защита работает только с процессами вашей обычной учётной записи. Запуск от администратора не поддерживается."
            alert.runModal()
            return
        }
        let instanceLock: ProtectionInstanceLock
        do {
            instanceLock = try ProtectionInstanceLock()
        } catch ProtectionInstanceLock.LockError.alreadyRunning {
            return
        } catch {
            let alert = NSAlert()
            alert.messageText = "Не удалось запустить защиту"
            alert.informativeText = "Нет доступа к локальному состоянию Russian Armor. Защита не включена. Проверьте права на папку данных приложения."
            alert.runModal()
            return
        }
        let watchdog = ApplicationWatchdog.start()
        app.setActivationPolicy(.accessory)
        let delegate = ArmorApplicationDelegate(watchdog: watchdog)
        app.delegate = delegate
        withExtendedLifetime((delegate, instanceLock)) { app.run() }
    }
}

@MainActor
private final class ArmorApplicationDelegate: NSObject, NSApplicationDelegate {
    private var statusMenu: NativeStatusMenu?
    private var windows: ArmorWindows?
    private var model: AppModel?
    private let watchdog: ApplicationWatchdog?
    private var watchdogTimer: Timer?
    private var terminationInProgress = false

    init(watchdog: ApplicationWatchdog?) {
        self.watchdog = watchdog
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppModel()
        self.model = model
        let windows = ArmorWindows(model: model)
        self.windows = windows
        statusMenu = NativeStatusMenu(model: model) { [weak windows] kind in windows?.open(kind) }

        // Respect the user's persisted login preference, including opt-out.
        if model.preferences.startAtLogin {
            do {
                try SMAppService.mainApp.register()
            } catch {
                model.recordWatchdogError("Автозапуск", detail: "Не удалось включить: \(error.localizedDescription)")
            }
        }

        model.updateWatchdogHealth(watchdog?.isHealthy == true)
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak watchdog, weak model] _ in
            Task { @MainActor in
                do {
                    try watchdog?.ensureRunning()
                    model?.updateWatchdogHealth(watchdog?.isHealthy == true)
                } catch {
                    model?.updateWatchdogHealth(false)
                    model?.recordWatchdogError("Watchdog: сбой", detail: error.localizedDescription)
                }
            }
        }
        configureMainMenu()
        if model.needsRuleSetup {
            DispatchQueue.main.async { [weak windows] in windows?.open(.readiness) }
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard model?.processProtection != nil else { return .terminateNow }
        if terminationInProgress { return .terminateLater }
        let alert = NSAlert()
        alert.messageText = "Закрыть Claude и выйти?"
        alert.icon = AppIcon.image
        alert.informativeText = "Сначала Russian Armor закроет распознанные процессы Claude Desktop и Claude Code. Только после этого завершится само приложение. Если Claude закрыть не удастся, выход будет отменён и защита продолжит работать."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Оставить защиту включённой")
        alert.addButton(withTitle: "Закрыть Claude и выйти")
        guard alert.runModal() == .alertSecondButtonReturn else { return .terminateCancel }

        terminationInProgress = true
        Task { [weak self, weak sender] in
            guard let self, let sender else { return }
            do {
                try await model?.closeClaudeBeforeApplicationExit()
                sender.reply(toApplicationShouldTerminate: true)
            } catch {
                terminationInProgress = false
                let failure = NSAlert()
                failure.messageText = "Russian Armor остаётся запущенным"
                failure.informativeText = (error as? LocalizedError)?.errorDescription
                    ?? "Не удалось закрыть Claude. Защита продолжает работать."
                failure.alertStyle = .warning
                failure.addButton(withTitle: "Закрыть")
                NSApp.activate(ignoringOtherApps: true)
                failure.runModal()
                sender.reply(toApplicationShouldTerminate: false)
            }
        }
        return .terminateLater
    }

    func applicationWillTerminate(_ notification: Notification) {
        watchdogTimer?.invalidate()
        do {
            try watchdog?.markCleanExit()
        } catch {
            model?.recordWatchdogError("Watchdog: ошибка при выходе", detail: error.localizedDescription)
        }
        model?.shutdownProtection()
    }

    private func configureMainMenu() {
        let root = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        let settings = NSMenuItem(title: "Настройки…", action: #selector(showSettings), keyEquivalent: ",")
        settings.target = self
        appMenu.addItem(settings)
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Выйти из Russian Armor", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        root.addItem(appItem)

        let editItem = NSMenuItem()
        editItem.title = "Правка"
        let editMenu = NSMenu(title: "Правка")
        editMenu.addItem(withTitle: "Копировать", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Выбрать всё", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        root.addItem(editItem)
        NSApp.mainMenu = root
    }

    @objc private func showSettings() { windows?.open(.settings) }
}

@MainActor
private final class ArmorWindows {
    private let model: AppModel
    private var controllers: [NativeStatusMenu.WindowKind: NSWindowController] = [:]

    init(model: AppModel) { self.model = model }

    func open(_ kind: NativeStatusMenu.WindowKind) {
        let controller: NSWindowController
        if let existing = controllers[kind] {
            controller = existing
        } else {
            let content: AnyView
            let title: String
            let size: NSSize
            switch kind {
            case .settings:
                content = AnyView(SettingsView(openHistory: { [weak self] in self?.open(.history) }).environmentObject(model))
                title = "Настройки — Russian Armor"
                size = SettingsLayout.defaultSize
            case .history:
                content = AnyView(HistoryView().environmentObject(model))
                title = "История — Russian Armor"
                size = NSSize(width: 620, height: 460)
            case .traffic:
                content = AnyView(TrafficView(monitor: model.traffic))
                title = "Соединения — Russian Armor"
                size = NSSize(width: 960, height: 600)
            case .readiness:
                content = AnyView(ReadinessView(
                    openSettings: { [weak self] in self?.open(.settings) },
                    close: { [weak self] in self?.controllers[.readiness]?.close() }
                ).environmentObject(model))
                title = "Защита — Russian Armor"
                size = NSSize(width: 460, height: 360)
            }
            let window = NSWindow(contentViewController: NSHostingController(rootView: content))
            window.title = title
            if kind == .traffic { window.isRestorable = false }
            window.styleMask = [.titled, .closable, .miniaturizable]
            if kind == .settings || kind == .history || kind == .traffic {
                window.styleMask.insert(.resizable)
                switch kind {
                case .settings: window.contentMinSize = SettingsLayout.minimumSize
                case .traffic: window.contentMinSize = NSSize(width: 860, height: 520)
                default: window.contentMinSize = NSSize(width: 540, height: 360)
                }
            }
            window.setContentSize(kind == .readiness ? window.contentView?.fittingSize ?? size : size)
            window.isReleasedWhenClosed = false
            window.center()
            controller = NSWindowController(window: window)
            controllers[kind] = controller
        }
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}
