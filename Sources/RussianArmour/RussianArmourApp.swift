import AppKit
import SwiftUI

@main
struct RussianArmourApp {
    @MainActor
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = ArmourApplicationDelegate()
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}

@MainActor
private final class ArmourApplicationDelegate: NSObject, NSApplicationDelegate {
    private var statusMenu: NativeStatusMenu?
    private var windows: ArmourWindows?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppModel()
        let windows = ArmourWindows(model: model)
        self.windows = windows
        statusMenu = NativeStatusMenu(model: model) { [weak windows] kind in windows?.open(kind) }
        configureMainMenu()
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
                content = AnyView(ReadinessView().environmentObject(model))
                title = "Защита — Russian Armour"
                size = NSSize(width: 510, height: 520)
            }
            let window = NSWindow(contentViewController: NSHostingController(rootView: content))
            window.title = title
            if kind == .traffic { window.isRestorable = false }
            window.styleMask = [.titled, .closable, .miniaturizable]
            if kind == .history || kind == .traffic {
                window.styleMask.insert(.resizable)
                window.contentMinSize = kind == .traffic ? NSSize(width: 860, height: 520) : NSSize(width: 540, height: 360)
            }
            window.setContentSize(size)
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
