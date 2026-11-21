import AppKit
import ArmorCore
import SwiftUI
import XCTest
@testable import RussianArmor

@MainActor
final class SettingsRenderingTests: XCTestCase {
    func testSettingsPagesRenderAtDefaultAndMinimumSizesWithoutRealProtection() async throws {
        guard ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_SETTINGS_TESTS"] == "1" else {
            throw XCTSkip("Opt-in GUI settings rendering")
        }
        _ = NSApplication.shared
        let suite = "SettingsRender.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let preferences = AppPreferences(vpnLocation: .router, automaticIPChecks: false, allowedCountryCode: "SE")
        defaults.set(try JSONEncoder().encode(preferences), forKey: "armor.preferences.v1")
        // Empty, injected process catalog: no real processes, network or user defaults.
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { provider in
            let json = provider == .ipWhoIS
                ? #"{"ip":"203.0.113.7","country_code":"SE","success":true}"#
                : #"{"ip":"203.0.113.7","country":"SE"}"#
            return try EgressObservation.decode(Data(json.utf8), provider: provider)
        }, processProtection: controller)
        defer { model.shutdownProtection() }
        model.refreshExternalIP()
        for _ in 0..<300 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        XCTAssertEqual(model.protection, .countryConfirmed)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-settings-render-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)

        for scheme in [ColorScheme.dark, .light] {
            for section in SettingsSection.allCases {
                try await render(model, section: section, scheme: scheme, size: SettingsLayout.defaultSize,
                                 name: "\(section.rawValue)-\(scheme == .dark ? "dark" : "light")", directory: directory)
            }
        }
        model.clearAllowedCountry()
        try await render(model, section: .protection, size: SettingsLayout.minimumSize,
                         name: "first-run-minimum", directory: directory)
        model.preferences.vpnLocation = .thisMac
        try await render(model, section: .protection, size: SettingsLayout.minimumSize,
                         name: "mac-minimum", directory: directory)
        var desktop = AccessRules(allowedCountries: ["NL", "SE"])
        desktop.deniedCountries = ["RU"]
        let profile = AccessProfile(name: "Раздельные правила для рабочих подключений", separateApplications: true,
                                    desktopRules: desktop, codeRules: .init(allowedCountries: ["DE"]))
        try model.saveAccessConfiguration(.init(profiles: [profile], activeProfileID: profile.id))
        model.preferences.vpnLocation = .router
        try await render(model, section: .protection, size: SettingsLayout.minimumSize,
                         name: "separate-rules-minimum", directory: directory)
        print("SETTINGS_RENDER_DIRECTORY: \(directory.path)")
    }

    private func render(_ model: AppModel, section: SettingsSection, scheme: ColorScheme = .dark,
                        size: NSSize, name: String, directory: URL) async throws {
        let root = SettingsView(initialSection: section).environmentObject(model).environment(\.colorScheme, scheme)
        let view = NSHostingView(rootView: root)
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Настройки — Russian Armor"
        window.isReleasedWhenClosed = false
        window.contentView = view
        window.appearance = NSAppearance(named: scheme == .dark ? .darkAqua : .aqua)
        window.center()
        window.orderFront(nil)
        defer { window.close() }
        try await Task.sleep(nanoseconds: 150_000_000)
        window.layoutIfNeeded()
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(view.frame.width, size.width, accuracy: 1)
        XCTAssertEqual(view.frame.height, size.height, accuracy: 1)
        // A resizable hosting view's fittingSize is its unconstrained ideal,
        // not its minimum size. Check the laid-out scroll documents instead.
        func checkScrollWidths(_ node: NSView) {
            if let scroll = node as? NSScrollView, let document = scroll.documentView {
                XCTAssertLessThanOrEqual(document.frame.width, scroll.contentView.bounds.width + 1,
                                         "Settings must wrap rather than require horizontal scrolling")
            }
            for child in node.subviews { checkScrollWidths(child) }
        }
        checkScrollWidths(view)
        // cacheDisplay does not capture SwiftUI's composited layers faithfully.
        // Capture the actual window to inspect native text and controls.
        let capture = Process()
        capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        capture.arguments = ["-x", "-o", "-l\(window.windowNumber)", directory.appendingPathComponent("\(name).png").path]
        try capture.run()
        capture.waitUntilExit()
        XCTAssertEqual(capture.terminationStatus, 0)
    }
}
