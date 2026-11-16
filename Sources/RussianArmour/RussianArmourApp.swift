import AppKit
import SwiftUI
import ServiceManagement

@main
struct RussianArmourApp {
    @MainActor
    static func main() {
        if ApplicationWatchdog.runHelperIfRequested() { return }
        let watchdog = ApplicationWatchdog.start()
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = ArmourApplicationDelegate(watchdog: watchdog)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}

@MainActor
private final class ArmourApplicationDelegate: NSObject, NSApplicationDelegate {
    private var statusMenu: NativeStatusMenu?
    private var windows: ArmourWindows?
    private var model: AppModel?
    private let watchdog: ApplicationWatchdog?
    private var watchdogTimer: Timer?

    init(watchdog: ApplicationWatchdog?) {
        self.watchdog = watchdog
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppModel()
        self.model = model
        let windows = ArmourWindows(model: model)
        self.windows = windows
        statusMenu = NativeStatusMenu(model: model) { [weak windows] kind in windows?.open(kind) }

        // Ensure autostart is enabled if protection is configured
        if model.preferences.allowedCountryCode != nil {
            do {
                try SMAppService.mainApp.register()
            } catch {
                model.recordWatchdogError("Автозапуск", detail: "Не удалось включить: \(error.localizedDescription)")
            }
        }

        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak watchdog, weak model] _ in
            Task { @MainActor in
                do {
                    try watchdog?.ensureRunning()
                } catch {
                    model?.recordWatchdogError("Watchdog: сбой", detail: error.localizedDescription)
                }
            }
        }
        configureMainMenu()
        if model.preferences.allowedCountryCode == nil {
            DispatchQueue.main.async { [weak windows] in windows?.open(.readiness) }
        }
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
        appMenu.addItem(withTitle: "Выйти из Russian Armour", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
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
private final class ArmourWindows {
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
                content = AnyView(SettingsView().environmentObject(model))
                title = "Настройки — Russian Armour"
                size = NSSize(width: 480, height: 520)
            case .history:
                content = AnyView(HistoryView().environmentObject(model))
                title = "История — Russian Armour"
                size = NSSize(width: 620, height: 460)
            case .traffic:
                content = AnyView(TrafficView(monitor: model.traffic))
                title = "Соединения — Russian Armour"
                size = NSSize(width: 960, height: 600)
            case .readiness:
                content = AnyView(ReadinessView(
                    openSettings: { [weak self] in self?.open(.settings) },
                    close: { [weak self] in self?.controllers[.readiness]?.close() }
                ).environmentObject(model))
                title = "Защита — Russian Armour"
                size = NSSize(width: 460, height: 360)
            }
            let window = NSWindow(contentViewController: NSHostingController(rootView: content))
            window.title = title
            if kind == .traffic { window.isRestorable = false }
            window.styleMask = [.titled, .closable, .miniaturizable]
            if kind == .history || kind == .traffic {
                window.styleMask.insert(.resizable)
                window.contentMinSize = kind == .traffic ? NSSize(width: 860, height: 520) : NSSize(width: 540, height: 360)
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
