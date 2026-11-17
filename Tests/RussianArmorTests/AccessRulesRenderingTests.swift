import AppKit
import ArmorCore
import SwiftUI
import XCTest
@testable import RussianArmor

@MainActor
final class AccessRulesRenderingTests: XCTestCase {
    func testEditorHasBoundedFrameAndRendersInGUIWithoutStartingProtection() async throws {
        guard ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_RULES_TESTS"] == "1" else {
            throw XCTSkip("Opt-in GUI rules editor rendering")
        }
        _ = NSApplication.shared
        let suite = "RulesRender.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked })
        XCTAssertNil(model.processProtection)
        let root = AccessRulesEditor(configuration: .migrating(country: "NL")).environmentObject(model)
            .environment(\.colorScheme, .dark)
        let view = NSHostingView(rootView: root)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 680), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = view
        window.appearance = NSAppearance(named: .darkAqua)
        window.orderFront(nil)
        defer { window.close() }
        try await Task.sleep(nanoseconds: 200_000_000)
        window.layoutIfNeeded()
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(view.fittingSize.width, 600, accuracy: 1)
        XCTAssertEqual(view.fittingSize.height, 680, accuracy: 1)
        let representation = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: representation)
        let png = try XCTUnwrap(representation.representation(using: .png, properties: [:]))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-rules-render-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let target = directory.appendingPathComponent("rules-editor.png")
        try png.write(to: target)
        print("RULES_EDITOR_RENDER: \(target.path)")
        let capture = Process()
        capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        let liveTarget = directory.appendingPathComponent("rules-editor-live.png")
        capture.arguments = ["-x", "-o", "-l\(window.windowNumber)", liveTarget.path]
        try capture.run()
        capture.waitUntilExit()
        XCTAssertEqual(capture.terminationStatus, 0)
        print("RULES_EDITOR_LIVE: \(liveTarget.path)")
    }
}
