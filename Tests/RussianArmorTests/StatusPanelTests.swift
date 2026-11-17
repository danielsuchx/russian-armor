import AppKit
import ArmorCore
import XCTest
@testable import RussianArmor

@MainActor
final class StatusPanelTests: XCTestCase {
    private func model(tunnels: [String] = [], reader: @escaping (EgressProvider) async throws -> EgressObservation = { _ in
        throw EgressError.invalidResponse
    }) throws -> AppModel {
        let name = "StatusPanelTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        defaults.set(try JSONEncoder().encode(AppPreferences(automaticIPChecks: false)), forKey: "armor.preferences.v1")
        addTeardownBlock { defaults.removePersistentDomain(forName: name) }
        return AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: {
            LocalDiagnosticsSnapshot(tunnels: .observed(tunnels), claudeDesktop: .running, checkedAt: Date())
        }, egressReader: reader)
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<100 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("External check did not settle")
    }

    func testCountryGuidanceFitsTwoLinesAtPanelWidth() {
        let storage = NSTextStorage(
            string: ProtectionState.countryConfirmed.detail,
            attributes: [.font: NSFont.systemFont(ofSize: 12)]
        )
        let layout = NSLayoutManager()
        let container = NSTextContainer(size: NSSize(
            width: StatusPanelLayout.width - 2 * StatusPanelLayout.inset,
            height: .greatestFiniteMagnitude
        ))
        container.lineFragmentPadding = 0
        layout.addTextContainer(container)
        storage.addLayoutManager(layout)
        var lines = 0
        layout.enumerateLineFragments(forGlyphRange: layout.glyphRange(for: container)) { _, _, _, _, _ in
            lines += 1
        }
        XCTAssertEqual(lines, 2, "Full guidance must fit without truncation or reducing the font")
    }

    func testContentSizedGeometryAndScreenEdgePlacement() {
        XCTAssertEqual(StatusPanelLayout.width, 340)
        XCTAssertEqual(StatusPanelLayout.labelWidth, 66)
        XCTAssertEqual(StatusPanelLayout.inset, 14)
        XCTAssertEqual(StatusPanelLayout.fieldHeight(for: "Страна подтверждена"), 20)
        XCTAssertEqual(StatusPanelLayout.fieldHeight(for: "Трафик не блокируется\nVPN-маршрут не проверен"), 40)
        let screen = NSRect(x: -1440, y: 0, width: 1440, height: 875)
        for height in [CGFloat(340), 420.5, 510] {
            for x in [CGFloat(-1440), -720, -20] {
                let frame = StatusPanelController.frame(
                    anchor: NSRect(x: x, y: 875, width: 24, height: 24),
                    visibleFrame: screen, contentHeight: height)
                XCTAssertEqual(frame.size, NSSize(width: 340, height: ceil(height)))
                XCTAssertTrue(screen.contains(frame), "Panel escaped the status item's display")
            }
        }
        let shortScreen = NSRect(x: 0, y: 0, width: 800, height: 400)
        let constrained = StatusPanelController.frame(
            anchor: NSRect(x: 700, y: 400, width: 24, height: 24),
            visibleFrame: shortScreen, contentHeight: 510)
        XCTAssertEqual(constrained.height, 388)
        XCTAssertTrue(shortScreen.contains(constrained))
    }

    func testContentGrowthKeepsTopPinnedWithoutResettingManualScroll() {
        XCTAssertTrue(StatusPanelController.shouldPinTop(
            previousDocumentHeight: 380,
            viewportHeight: 380,
            scrollOrigin: 42,
            topOrigin: 0
        ), "A disclosure expanding previously visible content must keep the panel header visible")
        XCTAssertTrue(StatusPanelController.shouldPinTop(
            previousDocumentHeight: 520,
            viewportHeight: 380,
            scrollOrigin: 0,
            topOrigin: 0
        ))
        XCTAssertFalse(StatusPanelController.shouldPinTop(
            previousDocumentHeight: 520,
            viewportHeight: 380,
            scrollOrigin: 42,
            topOrigin: 0
        ), "A user-scrolled panel must keep its manual position")
    }

    func testInitialContentDoesNotInventProtectionVPNOrCodeSessions() throws {
        let model = try model()
        let content = StatusPanelContent(model: model)
        XCTAssertEqual(model.protection.title, "Защита недоступна")
        XCTAssertEqual(content.protection, "Трафик не блокируется\nVPN-маршрут не проверен")
        XCTAssertEqual(content.vpn, "Не указано")
        XCTAssertEqual(content.claude, "открыт")
        XCTAssertEqual(content.ipv6, "Утечки не проверены")
        XCTAssertEqual(content.country, "Не проверена")
        XCTAssertEqual(content.ipAction, .checkIP)
        XCTAssertFalse(content.claude.contains("сессий"))
    }

    func testVPNLocationAndTunnelNameAreExplicitAndRespectPrivacySetting() throws {
        let model = try model(tunnels: ["utun4", "utun5"])
        model.preferences.vpnLocation = .router
        XCTAssertEqual(StatusPanelContent(model: model).vpn, "На роутере")
        model.preferences.vpnLocation = .thisMac
        XCTAssertEqual(StatusPanelContent(model: model).vpn, "На Mac · utun4 (+1)")
        model.preferences.showInterfaceNames = false
        XCTAssertEqual(StatusPanelContent(model: model).vpn, "На этом Mac")
    }

    func testObservedCountryAndIPUseActualProviderResultWithoutPinnedClaim() async throws {
        let observation = try EgressObservation.decode(Data(#"{"ip":"2001:db8::7","country":"NL"}"#.utf8))
        let model = try model(reader: { _ in observation })
        model.checkExternalIPAfterConsent()
        await settle(model)
        let content = StatusPanelContent(model: model)
        XCTAssertEqual(content.country, "NL (Нидерланды)")
        XCTAssertEqual(content.ip, observation.ip)
        XCTAssertFalse(content.country.contains("закреплена"))
        XCTAssertTrue(content.externalDetail.contains("IPinfo"))
        XCTAssertNil(content.ipAction)
    }

    func testCheckingFailureAndSleepRemainVisibleRatherThanLookingSuccessful() async throws {
        let model = try model(reader: { _ in throw URLError(.secureConnectionFailed) })
        model.checkExternalIPAfterConsent()
        XCTAssertEqual(StatusPanelContent(model: model).ip, "Проверяется…")
        await settle(model)
        let failure = StatusPanelContent(model: model)
        XCTAssertEqual(failure.country, "Не определена")
        XCTAssertEqual(failure.ip, "Ошибка проверки…")
        XCTAssertEqual(failure.ipAction, .failureDetails)
        XCTAssertTrue(failure.externalDetail.contains("TLS"))
        model.preferences.automaticIPChecks = true
        model.prepareForSleep()
        XCTAssertEqual(StatusPanelContent(model: model).ip, "Проверка приостановлена")
    }

    func testAutomaticCheckFeedbackDoesNotClaimProtectionOrOverrideOptOut() async throws {
        let observation = try EgressObservation.decode(Data(#"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#.utf8), provider: .ipWhoIS)
        let model = try model(reader: { _ in observation })
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsAction, .settings)
        model.preferences.automaticIPChecks = true
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsSummary, "Автопроверка IP ожидает доступную сеть")
        model.refreshExternalIP()
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsSummary, "Проверяем IP и страну…")
        await settle(model)
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsSummary, "IP и страна обновляются автоматически")
        XCTAssertNil(StatusPanelContent(model: model).diagnosticsAction)
        XCTAssertEqual(model.protection, .notConfigured)
        model.prepareForSleep()
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsSummary, "Проверки приостановлены до пробуждения")
        XCTAssertNil(StatusPanelContent(model: model).diagnosticsAction)
        model.resumeAfterWake()
        model.preferences.automaticIPChecks = false
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsAction, .settings)
        XCTAssertFalse(model.preferences.automaticIPChecks)
    }

    func testFailureFeedbackOffersDetailsAndDistinguishesAutomaticRetry() async throws {
        let model = try model(reader: { _ in throw URLError(.timedOut) })
        model.refreshExternalIP()
        await settle(model)
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsSummary, "IP не определён · подробности…")
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsAction, .failureDetails)
        model.preferences.automaticIPChecks = true
        model.refreshExternalIP()
        await settle(model)
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsSummary, "IP не определён · повторим автоматически")
        XCTAssertEqual(StatusPanelContent(model: model).diagnosticsAction, .failureDetails)
        XCTAssertEqual(model.protection, .notConfigured)
    }

    func testOnlyFourNewestActualEventsAreDisplayed() throws {
        let model = try model()
        for _ in 0..<4 {
            model.prepareForSleep()
            model.resumeAfterWake()
        }
        let content = StatusPanelContent(model: model)
        XCTAssertEqual(content.events, Array(model.journal.events.prefix(4)))
        XCTAssertEqual(content.events.map(\.kind), [.wake, .sleep, .wake, .sleep])
        model.clearHistory()
        XCTAssertTrue(StatusPanelContent(model: model).events.isEmpty)
    }

    func testUnavailableReferenceActionsCannotRunAtControllerBoundary() throws {
        XCTAssertEqual(StatusPanelAction.launchClaude.title, "Запустить Claude безопасно")
        _ = NSApplication.shared
        let model = try model()
        var opened: [NativeStatusMenu.WindowKind] = []
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { opened.append($0) }
        let previous = model.journal
        for action in [StatusPanelAction.launchClaude, .closeClaude, .pause15, .pause60] {
            XCTAssertTrue(action.requiresEnforcement)
            controller.performPanelAction(action)
        }
        XCTAssertTrue(opened.isEmpty)
        XCTAssertEqual(model.journal, previous)
        XCTAssertEqual(model.protection, .notConfigured)
        controller.performPanelAction(.history)
        controller.performPanelAction(.settings)
        controller.performPanelAction(.readiness)
        XCTAssertEqual(opened, [.history, .settings, .readiness])
    }

    func testBothMouseButtonsToggleOnlyTheCustomPanel() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI status-item click check")
        let app = NSApplication.shared
        let controller = NativeStatusMenu(model: try model()) { _ in }
        let item = try XCTUnwrap(controller.statusItem)
        defer {
            controller.panel.close()
            NSStatusBar.system.removeStatusItem(item)
        }
        let button = try XCTUnwrap(item.button)
        let window = try XCTUnwrap(button.window)
        let point = button.convert(NSPoint(x: button.bounds.midX, y: button.bounds.midY), to: nil)
        XCTAssertNil(item.menu, "Neither mouse button should use a native status menu")
        XCTAssertFalse(try XCTUnwrap(button.toolTip).contains("Правый клик"))

        let clickMask: NSEvent.EventTypeMask = [.leftMouseDown, .rightMouseDown]
        XCTAssertEqual(button.sendAction(on: clickMask), Int(clickMask.rawValue))

        func click(_ type: NSEvent.EventType, losesFocus: Bool = false) throws {
            let event = try XCTUnwrap(NSEvent.mouseEvent(
                with: type, location: point, modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber, context: nil,
                eventNumber: 0, clickCount: 1, pressure: 0
            ))
            // Status-item tracking belongs to the system menu-bar process. Feed
            // the event context here, then exercise the configured target/action.
            app.postEvent(event, atStart: true)
            let mask: NSEvent.EventTypeMask = type == .leftMouseDown ? .leftMouseDown : .rightMouseDown
            _ = try XCTUnwrap(app.nextEvent(matching: mask, until: Date(), inMode: .default, dequeue: true))
            XCTAssertEqual(app.currentEvent?.type, type)
            if losesFocus {
                controller.panel.handleGlobalMouseDown(at: window.convertToScreen(NSRect(origin: point, size: .zero)).origin)
                XCTAssertTrue(controller.panel.window.isVisible, "The anchor click belongs to the button action")
                // Menu-bar tracking can take key focus before invoking the action.
                controller.panel.windowDidResignKey(Notification(name: NSWindow.didResignKeyNotification,
                                                                 object: controller.panel.window))
            }
            XCTAssertTrue(button.sendAction(try XCTUnwrap(button.action), to: button.target))
        }

        for type in [NSEvent.EventType.leftMouseDown, .rightMouseDown] {
            try click(type)
            XCTAssertTrue(controller.panel.window.isVisible, "\(type) should open the custom panel")
            try click(type, losesFocus: true)
            XCTAssertFalse(controller.panel.window.isVisible, "\(type) should close the custom panel")
        }
        // Switching buttons while the panel is open must still toggle the same surface.
        try click(.leftMouseDown)
        XCTAssertTrue(controller.panel.window.isVisible)
        try click(.rightMouseDown)
        XCTAssertFalse(controller.panel.window.isVisible)
    }

    func testFocusLossClosesPanelButCannotDismissANewerPresentation() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI focus lifecycle check")
        _ = NSApplication.shared
        let panel = StatusPanelController(model: try model()) { _ in }
        defer { panel.close() }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        let anchor = NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24)
        panel.show(anchor: anchor, visibleFrame: screen)
        panel.window.resignKey()
        panel.close()
        panel.show(anchor: anchor, visibleFrame: screen)
        try await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertTrue(panel.window.isVisible, "A stale focus-loss dismissal must not close a reopened panel")

        panel.window.resignKey()
        try await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertFalse(panel.window.isVisible, "Ordinary focus loss should still dismiss the panel")

        panel.show(anchor: anchor, visibleFrame: screen)
        panel.handleGlobalMouseDown(at: NSPoint(x: screen.minX, y: screen.minY))
        XCTAssertFalse(panel.window.isVisible, "A click outside the icon should still dismiss the panel")
    }

    func testPanelClosesBeforeOpeningAWindowAndOnEscape() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI lifecycle check: RUSSIAN_ARMOR_RENDER_PANEL_TESTS=1 swift test --filter StatusPanelTests")
        _ = NSApplication.shared
        let model = try model()
        var opened: NativeStatusMenu.WindowKind?
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { opened = $0 }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        controller.panel.show(anchor: NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24), visibleFrame: screen)
        XCTAssertTrue(controller.panel.window.isVisible)
        controller.panel.window.cancelOperation(nil)
        XCTAssertFalse(controller.panel.window.isVisible)
        controller.panel.show(anchor: NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24), visibleFrame: screen)
        controller.performPanelAction(.readiness)
        XCTAssertFalse(controller.panel.window.isVisible)
        XCTAssertEqual(opened, .readiness)
    }

    func testDisclosureGrowsDownwardWithoutScrollingOrMovingTheTop() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI disclosure check")
        _ = NSApplication.shared
        let model = try model()
        let panel = StatusPanelController(model: model) { _ in }
        defer { panel.close() }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        panel.show(anchor: NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24), visibleFrame: screen)
        try await Task.sleep(nanoseconds: 100_000_000)
        let collapsed = panel.window.frame
        let view = try XCTUnwrap(panel.window.contentView?.subviews.first)
        for _ in 0..<3 {
            panel.presentation.showsDiagnostics.toggle()
            for _ in 0..<20 {
                try await Task.sleep(nanoseconds: 10_000_000)
                XCTAssertEqual(panel.window.frame.maxY, collapsed.maxY, accuracy: 0.5)
                XCTAssertEqual(view.frame.origin, .zero)
                XCTAssertEqual(view.bounds.origin, .zero)
                XCTAssertNil(view.enclosingScrollView)
            }
            XCTAssertGreaterThan(panel.window.frame.height, collapsed.height + 90)
            panel.presentation.showsDiagnostics.toggle()
            try await Task.sleep(nanoseconds: 100_000_000)
            XCTAssertEqual(panel.window.frame.height, collapsed.height, accuracy: 1)
            XCTAssertEqual(panel.window.frame.maxY, collapsed.maxY, accuracy: 0.5)
        }
    }

    func testDisclosureResizesWindowBeforeTheHostingLayoutReturns() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI same-frame layout check")
        _ = NSApplication.shared
        let model = try model()
        let panel = StatusPanelController(model: model) { _ in }
        defer { panel.close() }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        panel.show(anchor: NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24), visibleFrame: screen)
        try await Task.sleep(nanoseconds: 100_000_000)
        let view = try XCTUnwrap(panel.window.contentView?.subviews.first)
        let collapsed = panel.window.frame
        for _ in 0..<3 {
            for expanded in [true, false] {
                panel.presentation.showsDiagnostics = expanded
                view.invalidateIntrinsicContentSize()
                view.needsLayout = true
                view.layoutSubtreeIfNeeded()
                // No run-loop yield: a deferred resize would expose the new
                // SwiftUI content inside the old window for one displayed frame.
                XCTAssertEqual(panel.window.frame.height, ceil(view.fittingSize.height), accuracy: 0.5)
                XCTAssertEqual(view.frame.size, panel.window.frame.size)
                XCTAssertEqual(panel.window.frame.maxY, collapsed.maxY, accuracy: 0.5)
                XCTAssertEqual(view.frame.origin, .zero)
                if expanded {
                    XCTAssertGreaterThan(panel.window.frame.height, collapsed.height + 90)
                } else {
                    XCTAssertEqual(panel.window.frame.height, collapsed.height, accuracy: 0.5)
                }
            }
        }
    }

    func testVisiblePanelShrinksAfterClearingHistoryAndScrollsOnShortDisplay() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI layout check")
        _ = NSApplication.shared
        let model = try model()
        for _ in 0..<4 { model.prepareForSleep(); model.resumeAfterWake() }
        let panel = StatusPanelController(model: model) { _ in }
        defer { panel.close() }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        let anchor = NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24)
        panel.show(anchor: anchor, visibleFrame: screen)
        try await Task.sleep(nanoseconds: 200_000_000)
        let fullHeight = panel.window.frame.height
        model.clearHistory()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(fullHeight - panel.window.frame.height, 3 * 19.5, accuracy: 1)
        let shortScreen = NSRect(x: screen.minX, y: screen.minY, width: screen.width, height: 250)
        panel.show(anchor: NSRect(x: shortScreen.midX, y: shortScreen.maxY, width: 24, height: 24),
                   visibleFrame: shortScreen)
        let viewport = try XCTUnwrap(panel.window.contentView?.subviews.first as? NSScrollView)
        let document = try XCTUnwrap(viewport.documentView)
        XCTAssertEqual(panel.window.frame.height, 238)
        XCTAssertGreaterThan(document.frame.height, viewport.contentSize.height)
        XCTAssertTrue(viewport.hasVerticalScroller)
    }

    func testRenderReferencePanelInActualWindow() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_PANEL_TESTS"] == "1",
                         "Opt-in GUI render: RUSSIAN_ARMOR_RENDER_PANEL_TESTS=1 swift test --filter StatusPanelTests")
        _ = NSApplication.shared
        let observation = try EgressObservation.decode(Data(#"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#.utf8), provider: .ipWhoIS)
        let model = try model(reader: { _ in observation })
        model.preferences.vpnLocation = .router
        model.preferences.automaticIPChecks = true
        model.refreshExternalIP()
        await settle(model)
        model.prepareForSleep()
        model.resumeAfterWake()
        model.refreshExternalIP()
        await settle(model)
        let panel = StatusPanelController(model: model) { _ in }
        defer { panel.close() }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        panel.show(anchor: NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24), visibleFrame: screen)
        try await Task.sleep(nanoseconds: 200_000_000)
        let view = try XCTUnwrap(panel.window.contentView?.subviews.first)
        XCTAssertNil(view.enclosingScrollView, "A fitting panel must grow rather than scroll")
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(view.bounds.width, 340)
        XCTAssertEqual(view.bounds.height, ceil(view.fittingSize.height), accuracy: 1)
        XCTAssertEqual(panel.window.frame.height, view.bounds.height, accuracy: 1)
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        try png.write(to: root.appendingPathComponent(".build/reference-panel.png"))
        XCTAssertGreaterThan(png.count, 10_000)
    }
}
