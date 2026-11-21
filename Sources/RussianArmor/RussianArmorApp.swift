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
    private var networkAlerts: NetworkInterceptionController?
    private var pendingImportURLs: [URL] = []
    private let watchdog: ApplicationWatchdog?
    private var watchdogTimer: Timer?
    private var terminationInProgress = false
    private var relaunchAfterUpdate = false

    init(watchdog: ApplicationWatchdog?) {
        self.watchdog = watchdog
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppModel()
        self.model = model
        model.updater.startAutomaticChecks()
        Task { await model.tunnelReaderRegistration.migrateEnabledReader() }
        let windows = ArmorWindows(model: model)
        self.windows = windows
        networkAlerts = NetworkInterceptionController(engine: model.networkEngine) { [weak windows, weak model] in
            model?.requestedSettingsSection = .guides
            windows?.open(.settings)
        }
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
        if !pendingImportURLs.isEmpty { application(NSApplication.shared, open: pendingImportURLs); pendingImportURLs = [] }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let model else { pendingImportURLs = urls; return }
        guard let url = urls.first(where: { $0.scheme == "zastava" }), url.absoluteString.utf8.count <= 65_536 else { return }
        // Deep links are reviewable input, never permission to change a route.
        model.networkEngine.importedRoute = url.absoluteString
        model.requestedSettingsSection = .routes
        windows?.open(.settings)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model else { return .terminateNow }
        if terminationInProgress { return .terminateLater }
        let update = model.updater.prepared
        guard model.processProtection != nil || update != nil else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = update == nil ? "Закрыть Claude и выйти?" : "Закрыть Claude и установить обновление?"
        alert.icon = AppIcon.image
        alert.informativeText = "Сначала Russian Armor закроет распознанные процессы Claude Desktop и Claude Code. Только после этого завершится само приложение. Если Claude закрыть не удастся, выход будет отменён и защита продолжит работать."
        if update != nil {
            alert.informativeText = "Russian Armor закроет Claude Desktop и Claude Code, установит проверенную версию и запустится снова."
        }
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Оставить защиту включённой")
        alert.addButton(withTitle: update == nil ? "Закрыть Claude и выйти" : "Установить и перезапустить")
        guard alert.runModal() == .alertSecondButtonReturn else {
            if update != nil { model.updater.discard() }
            return .terminateCancel
        }

        terminationInProgress = true
        Task { [weak self, weak sender] in
            guard let self, let sender else { return }
            do {
                if update == nil {
                    await model.updater.cancelDownloadForExit()
                } else if watchdog?.isHealthy != true {
                    throw AppUpdateError.watchdog
                }
                try await model.closeClaudeBeforeApplicationExit()
                try await model.networkEngine.shutdown()
                if let update {
                    do {
                        guard watchdog?.isHealthy == true else { throw AppUpdateError.watchdog }
                        try update.install()
                    } catch {
                        model.processProtection?.resumeAfterCancelledExit(reason: "Установка прервана. Проверяем защиту.")
                        model.refreshExternalIP()
                        throw error
                    }
                    relaunchAfterUpdate = true
                    model.updater.discard()
                }
                sender.reply(toApplicationShouldTerminate: true)
            } catch {
                terminationInProgress = false
                if update != nil { model.updater.discard(error: error) }
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
            try watchdog?.markCleanExit(relaunch: relaunchAfterUpdate)
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
final class ArmorWindows: NSObject, NSWindowDelegate {
    private let model: AppModel
    private var controllers: [NativeStatusMenu.WindowKind: NSWindowController] = [:]
    private var frames: [NativeStatusMenu.WindowKind: NSRect] = [:]

    init(model: AppModel) { self.model = model; super.init() }

    @discardableResult
    func open(_ kind: NativeStatusMenu.WindowKind) -> NSWindowController {
        let controller: NSWindowController
        if let existing = controllers[kind] {
            controller = existing
        } else {
            let content: AnyView
            let title: String
            let size: NSSize
            switch kind {
            case .settings:
                content = AnyView(SettingsView(initialSection: model.requestedSettingsSection ?? .protection, openHistory: { [weak self] in self?.open(.history) }).environmentObject(model))
                title = "Настройки — Russian Armor"
                size = SettingsLayout.defaultSize
            case .history:
                content = AnyView(HistoryView().environmentObject(model))
                title = "История — Russian Armor"
                size = NSSize(width: 620, height: 460)
            case .traffic:
                content = AnyView(TrafficView(monitor: model.traffic).modifier(NetworkPrivacyModifier(engine: model.networkEngine)))
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
            if let frame = frames[kind] { window.setFrame(frame, display: false) }
            else { window.center() }
            window.delegate = self
            controller = NSWindowController(window: window)
            controllers[kind] = controller
        }
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        return controller
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow,
              let kind = controllers.first(where: { $0.value.window === window })?.key else { return }
        frames[kind] = window.frame
        // A closed hosting controller keeps observing every model update.
        // Release its view graph; the protection model continues independently.
        window.contentViewController = nil
        controllers.removeValue(forKey: kind)
    }
}
