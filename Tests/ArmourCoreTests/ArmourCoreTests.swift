import Foundation
import XCTest
@testable import ArmourCore

final class ArmourCoreTests: XCTestCase {
    func testScaffoldNeverClaimsProtection() {
        let protection = ProtectionState.notConfigured
        XCTAssertEqual(protection.title, "Защита не настроена")
        XCTAssertFalse(protection.canSafelyLaunch)
        XCTAssertFalse(protection.canPause)
        XCTAssertEqual(protection.symbol, "shield.slash")
    }

    func testConnectivityDoesNotChangeProtectionState() {
        for state in [Connectivity.checking, .available, .requiresConnection, .unavailable] {
            let snapshot = NetworkSnapshot(connectivity: state)
            XCTAssertEqual(snapshot.connectivity, state)
            XCTAssertEqual(ProtectionState.notConfigured.title, "Защита не настроена")
        }
    }

    func testInterfacesAreUniqueAndSorted() {
        let snapshot = NetworkSnapshot(
            connectivity: .available,
            availableInterfaces: ["utun4", "en0", "en0"]
        )
        XCTAssertEqual(snapshot.availableInterfaces, ["en0", "utun4"])
        XCTAssertNil(snapshot.checkedAt)
    }

    func testInitialSnapshotIsNotAnActualCheck() {
        XCTAssertEqual(NetworkSnapshot.checking.connectivity, .checking)
        XCTAssertNil(NetworkSnapshot.checking.checkedAt)
        XCTAssertTrue(NetworkSnapshot.checking.availableInterfaces.isEmpty)
    }

    func testJournalKeepsNewestHundredEvents() {
        var journal = EventJournal()
        for index in 0..<125 {
            journal.record(ActivityEvent(title: "Event \(index)"))
        }
        XCTAssertEqual(journal.events.count, EventJournal.capacity)
        XCTAssertEqual(journal.events.first?.title, "Event 124")
        XCTAssertEqual(journal.events.last?.title, "Event 25")
    }

    func testJournalRoundTrip() throws {
        let event = ActivityEvent(date: Date(timeIntervalSince1970: 1000), kind: .warning, title: "Сеть недоступна")
        let journal = EventJournal(events: [event])
        let data = try JSONEncoder().encode(journal)
        XCTAssertEqual(try JSONDecoder().decode(EventJournal.self, from: data), journal)
    }

    func testSleepAndWakeSymbolsAndJournalRoundTrip() throws {
        XCTAssertEqual(ActivityEvent.Kind.sleep.symbol, "moon.zzz")
        XCTAssertEqual(ActivityEvent.Kind.wake.symbol, "sun.max")
        let kinds: [ActivityEvent.Kind] = [.information, .network, .warning, .sleep, .wake]
        let journal = EventJournal(events: kinds.map { ActivityEvent(kind: $0, title: $0.rawValue) })
        let data = try JSONEncoder().encode(journal)
        XCTAssertEqual(try JSONDecoder().decode(EventJournal.self, from: data), journal)
    }

    func testDecodedJournalAlsoEnforcesCapacity() throws {
        struct StoredJournal: Encodable { let events: [ActivityEvent] }
        let oversized = StoredJournal(events: (0..<150).map { ActivityEvent(title: "\($0)") })
        let restored = try JSONDecoder().decode(EventJournal.self, from: JSONEncoder().encode(oversized))
        XCTAssertEqual(restored.events.count, EventJournal.capacity)
        XCTAssertEqual(restored.events.first?.title, "0")
    }

    func testClearHistory() {
        var journal = EventJournal(events: [ActivityEvent(title: "Started")])
        journal.clear()
        XCTAssertTrue(journal.events.isEmpty)
    }

    func testCorruptedJournalIsRejected() {
        XCTAssertThrowsError(try JSONDecoder().decode(EventJournal.self, from: Data("not json".utf8)))
    }

    func testPreferencesRoundTrip() throws {
        let preferences = AppPreferences(showInterfaceNames: false, recordNetworkEvents: false)
        let restored = try JSONDecoder().decode(AppPreferences.self, from: JSONEncoder().encode(preferences))
        XCTAssertEqual(restored, preferences)
    }
}
