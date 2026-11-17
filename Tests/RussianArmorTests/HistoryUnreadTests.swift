import ArmorCore
import AppKit
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class HistoryUnreadTests: XCTestCase {
    private func model() throws -> (AppModel, UserDefaults) {
        let suite = "HistoryUnreadTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.set(try JSONEncoder().encode(AppPreferences(automaticIPChecks: false)), forKey: "armor.preferences.v1")
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return (AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked },
                         trafficReader: { TrafficSnapshot(connections: []) }), defaults)
    }

    func testUnreadStatePersistsAndNewEventsDoNotBecomeReadAutomatically() throws {
        let (model, defaults) = try model()
        XCTAssertEqual(model.journal.unreadCount, 1)
        model.markHistoryRead()
        let stored = try JSONDecoder().decode(EventJournal.self, from: XCTUnwrap(defaults.data(forKey: "armor.journal.v1")))
        XCTAssertEqual(stored.unreadCount, 0)
        XCTAssertEqual(stored.events.count, 1)
        model.recordWatchdogError("Warning", detail: "Details")
        XCTAssertEqual(model.journal.unreadCount, 1)
        let restored = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked })
        XCTAssertEqual(restored.journal.unreadCount, 2, "Previous unread event plus new launch event")
        restored.clearHistory()
        XCTAssertEqual(restored.journal.unreadCount, 0)
        XCTAssertTrue(restored.journal.events.isEmpty)
    }

    func testPanelAndNativeMenuDoNotMarkReadAndShowCount() throws {
        let (model, _) = try model()
        let menu = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        _ = StatusPanelContent(model: model)
        menu.updateContents()
        XCTAssertEqual(model.journal.unreadCount, 1)
        XCTAssertTrue(menu.menu.items.contains { $0.title == "Вся история…" })
        XCTAssertTrue(menu.menu.items.contains { $0.title == "Последние события · новых: 1" })
        XCTAssertTrue(menu.menu.items.contains { $0.title.hasPrefix("● ") })
        model.markHistoryRead()
        menu.updateContents()
        XCTAssertTrue(menu.menu.items.contains { $0.title == "Вся история…" })
        XCTAssertTrue(menu.menu.items.contains { $0.title == "Последние события" })
        XCTAssertFalse(menu.menu.items.contains { $0.title.hasPrefix("● ") })
    }

    func testHappEventRespectsConsentAndRecordingAndContainsNoAddresses() async throws {
        let (model, defaults) = try model()
        let countBefore = model.journal.events.count
        model.happConnections.onMultipleAddresses?(2)
        XCTAssertEqual(model.journal.events.count, countBefore, "No collection without consent")
        model.traffic.start()
        model.happConnections.onMultipleAddresses?(2)
        let event = try XCTUnwrap(model.journal.events.first)
        XCTAssertEqual(event.title, "У Happ несколько внешних адресов")
        XCTAssertTrue(event.detail.contains("число VPN-серверов"))
        XCTAssertTrue(model.journal.isUnread(event))
        let stored = String(decoding: try XCTUnwrap(defaults.data(forKey: "armor.journal.v1")), as: UTF8.self)
        XCTAssertFalse(stored.contains("8.8.8.8"))
        XCTAssertFalse(stored.contains("1.1.1.1"))
        let countAfter = model.journal.events.count
        model.preferences.recordNetworkEvents = false
        model.happConnections.onMultipleAddresses?(3)
        XCTAssertEqual(model.journal.events.count, countAfter)
        model.traffic.stop()
    }
}
