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
        try await renderView(root, scheme: scheme, size: size, name: name, directory: directory)
    }

    func testConnectedNativeNetworkPagesAndInterceptionRenderWithMockData() async throws {
        guard ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_SETTINGS_TESTS"] == "1" else {
            throw XCTSkip("Opt-in GUI settings rendering")
        }
        _ = NSApplication.shared
        let suite = "NetworkRender.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let route: EngineValue = .object(["id": .string("example"), "label": .string("Рабочий маршрут"), "enabled": .bool(true),
            "country": .string("NL"), "exit_ip": .string("203.0.113.9"), "status": .string("active"),
            "entries": .array([.object(["proto": .string("socks5"), "host": .string("proxy.example.org"), "port": .number(1080)])])])
        let profile: EngineValue = .object(["id": .string("default"), "name": .string("Основной"), "is_active": .bool(true)])
        let check: EngineValue = .object(["status": .string("unknown"), "code": .string("DNS_UNAVAILABLE"),
            "message": .string("Один из источников не ответил. Свежего результата нет."), "reason": .string("timeout")])
        let engine = NetworkEngineStore(defaults: defaults, transport: { command, _ in
            switch command {
            case "get_state": return .object(["interception_behavior": .string("ask_popup"), "cli_mode": .string("ai_only")])
            case "get_gateway_stats": return .object(["active_ai_tunnels": .number(2), "protected_ai_requests": .number(12)])
            case "get_guard_pause_status_cmd": return .object(["gate": .string("open"), "paused": .bool(false)])
            case "get_sysproxy_status", "check_cli_protection_status": return .bool(true)
            case "get_cli_settings": return .object(["cli_mode": .string("ai_only")])
            case "list_routes": return .object(["routes": .array([route])])
            case "get_coverage_snapshot": return .object(["gateway_addr": .string("127.0.0.1:8899"), "pac_url": .string("http://127.0.0.1:8899/proxy.pac"), "apps": .array([
                .object(["id": .string("claude-desktop"), "name": .string("Claude Desktop"), "status": .string("confirmed"), "detail": .string("Шлюз видел запрос приложения."), "ai_requests": .number(12)]),
                .object(["id": .string("jetbrains"), "name": .string("JetBrains"), "status": .string("unknown"), "detail": .string("Автоматическая настройка не подтверждена."), "manual_steps": .array([.string("jetbrains_proxy_settings")])])])])
            case "list_claude_profiles_cmd": return .object(["profiles": .array([profile])])
            case "audit_connection": return .object(["telemetry": .object(["ip": .string("203.0.113.9"), "country_code": .string("NL")]), "incomplete": .bool(true), "unknown_count": .number(14), "checks": .array(Array(repeating: check, count: 14))])
            case "native_poll_events": return .array([])
            default: return .null
            }
        })
        await engine.refresh()
        engine.audit("anthropic")
        for _ in 0..<500 { if !engine.busy.contains("audit-anthropic") { break }; await Task.yield() }
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                             egressReader: { _ in throw URLError(.notConnectedToInternet) }, processProtection: controller,
                             networkEngine: engine)
        defer { model.shutdownProtection() }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-native-network-render-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        for scheme in [ColorScheme.dark, .light] {
            for section in [SettingsSection.network, .routes, .audit, .coverage, .backup, .guides] {
                let root = SettingsView(initialSection: section).environmentObject(model).environment(\.colorScheme, scheme)
                try await renderView(root, scheme: scheme, size: SettingsLayout.defaultSize,
                                     name: "\(section.rawValue)-\(scheme == .dark ? "dark" : "light")", directory: directory)
            }
        }
        try await render(model, section: .network, scheme: .light, size: SettingsLayout.minimumSize,
                         name: "network-minimum", directory: directory)
        engine.receiveEvent(.object(["name": .string("interceptor://risk-detected"), "payload": .object([
            "id": .string("test"), "provider": .string("anthropic"), "scope": .string("network"), "phase": .string("ready"),
            "gate_reason": .string("Страна выхода изменилась. Требуется решение."),
            "network_change": .object(["old_country": .string("NL"), "new_country": .string("DE"), "old_ip": .string("203.0.113.9"), "new_ip": .string("203.0.113.10")])])]))
        let popup = NetworkInterceptionView(engine: engine, openGuide: {}).environment(\.colorScheme, .dark)
        let popupSize = NSHostingView(rootView: popup).fittingSize
        try await renderView(popup, scheme: .dark, size: popupSize, name: "interception-dark", directory: directory)
        print("NETWORK_RENDER_DIRECTORY: \(directory.path)")
    }

    func testDiagnosticReportPreviewRendersWithoutRealProtection() async throws {
        guard ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_SETTINGS_TESTS"] == "1" else {
            throw XCTSkip("Opt-in GUI settings rendering")
        }
        _ = NSApplication.shared
        let report = DiagnosticReport(createdAt: Date(), appVersion: "0.2.2", vpnLocation: .router,
                                      controllerState: .paused, checks: [
            .init(.egress, .stale, .noFreshEgress), .init(.claudeRoutes, .unavailable, .partialSnapshot),
            .init(.dnsConfiguration, .observed, .configuredDNSOnly), .init(.desktopEndpoint, .disabled, .disabled),
            .init(.codeEndpoint, .disabled, .disabled), .init(.watchdog, .observed, .watchdogResponding)
        ])
        let export = try DiagnosticExport(report: report)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-report-render-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        for scheme in [ColorScheme.dark, .light] {
            let root = DiagnosticReportPreview(export: export).environment(\.colorScheme, scheme)
            try await renderView(root, scheme: scheme, size: NSSize(width: 600, height: 580),
                                 name: "report-\(scheme == .dark ? "dark" : "light")", directory: directory)
        }
        print("REPORT_RENDER_DIRECTORY: \(directory.path)")
    }

    private func renderView<Content: View>(_ root: Content, scheme: ColorScheme, size: NSSize,
                                          name: String, directory: URL) async throws {
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
