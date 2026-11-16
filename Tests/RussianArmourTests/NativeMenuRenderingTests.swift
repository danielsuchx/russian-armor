import AppKit
import ArmourCore
import XCTest
@testable import RussianArmour

/// Opt-in integration check: opens the real NSMenu in a macOS GUI session.
/// Unlike image != nil, this checks the image views AppKit actually displays.
@MainActor
final class NativeMenuRenderingTests: XCTestCase {
    func testNativeMenuDisplaysIconsInLightAndDarkAppearances() async throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["RUSSIAN_ARMOUR_RENDER_MENU_TESTS"] == "1",
            "Requires a GUI session: RUSSIAN_ARMOUR_RENDER_MENU_TESTS=1 swift test --filter NativeMenuRenderingTests"
        )
        let app = NSApplication.shared
        let previousAppearance = app.appearance
        defer { app.appearance = previousAppearance }
        let name = "NativeMenuRenderingTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: {
            LocalDiagnosticsSnapshot(tunnels: .observed([]), claudeDesktop: .running, checkedAt: Date())
        })
        model.prepareForSleep()
        model.resumeAfterWake()
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        let menu = controller.menu
        let expectedCount = menu.items.filter { !$0.isHidden && $0.image != nil }.count
        XCTAssertGreaterThan(expectedCount, 10)

        for (theme, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            app.appearance = try XCTUnwrap(NSAppearance(named: appearance))
            let visibleBefore = Set(app.windows.filter(\.isVisible).map(ObjectIdentifier.init))
            var inspected = false
            let inspection = MenuInspection {
                defer { menu.cancelTracking() }
                guard let window = app.windows.first(where: {
                    $0.isVisible && !visibleBefore.contains(ObjectIdentifier($0))
                }), let content = window.contentView else {
                    XCTFail("Native menu did not open (\(theme))")
                    return
                }
                inspected = true
                let icons = self.descendants(of: content).compactMap { $0 as? NSImageView }
                    .filter { !$0.isHiddenOrHasHiddenAncestor && !$0.bounds.isEmpty }
                XCTAssertEqual(icons.count, expectedCount, "Missing native menu image views (\(theme))")
                for (index, icon) in icons.enumerated() {
                    guard let bitmap = icon.bitmapImageRepForCachingDisplay(in: icon.bounds) else {
                        XCTFail("Cannot render icon \(index) (\(theme))")
                        continue
                    }
                    icon.cacheDisplay(in: icon.bounds, to: bitmap)
                    let hasVisiblePixels = (0..<bitmap.pixelsHigh).contains { y in
                        (0..<bitmap.pixelsWide).contains { x in
                            (bitmap.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.05
                        }
                    }
                    XCTAssertTrue(hasVisiblePixels, "Empty icon \(index) (\(theme))")
                }
                // Capture only this test's menu view, never the desktop or other apps.
                if let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds) {
                    content.cacheDisplay(in: content.bounds, to: bitmap)
                    if let data = bitmap.representation(using: .png, properties: [:]) {
                        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
                            .deletingLastPathComponent().deletingLastPathComponent()
                        let output = root.appendingPathComponent(".build/native-menu-\(theme).png")
                        do { try data.write(to: output) }
                        catch { XCTFail("Cannot save menu render: \(error)") }
                    }
                }
            }
            let timer = Timer(timeInterval: 0.25, target: inspection,
                              selector: #selector(MenuInspection.fire(_:)), userInfo: nil, repeats: false)
            RunLoop.main.add(timer, forMode: .common)
            RunLoop.main.add(timer, forMode: .eventTracking)
            let frame = try XCTUnwrap(NSScreen.main).visibleFrame
            menu.popUp(positioning: nil, at: NSPoint(x: frame.minX + 80, y: frame.maxY - 20), in: nil)
            timer.invalidate()
            XCTAssertTrue(inspected, "Native menu was not inspected (\(theme))")
        }
    }

    @MainActor
    private final class MenuInspection: NSObject {
        private let inspect: @MainActor () -> Void

        init(inspect: @escaping @MainActor () -> Void) {
            self.inspect = inspect
        }

        @objc func fire(_ timer: Timer) { inspect() }
    }

    private func descendants(of view: NSView) -> [NSView] {
        [view] + view.subviews.flatMap { descendants(of: $0) }
    }
}
