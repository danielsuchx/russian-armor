import Foundation
import XCTest
@testable import ArmorCore

final class EventJournalUnreadTests: XCTestCase {
    func testNewEventsAreUnreadAndMarkAllReadPreservesHistory() {
        var journal = EventJournal()
        let event = ActivityEvent(title: "New")
        journal.record(event)
        XCTAssertTrue(journal.isUnread(event))
        XCTAssertEqual(journal.unreadCount, 1)
        journal.markAllRead()
        XCTAssertEqual(journal.events, [event])
        XCTAssertEqual(journal.unreadCount, 0)
        journal.record(ActivityEvent(title: "Next"))
        XCTAssertEqual(journal.unreadCount, 1)
        journal.clear()
        XCTAssertTrue(journal.events.isEmpty)
        XCTAssertEqual(journal.unreadCount, 0)
    }

    func testUnreadIDsSurviveRestartAndArePrunedAtCapacity() throws {
        var journal = EventJournal()
        for index in 0..<125 { journal.record(ActivityEvent(title: "Event \(index)")) }
        XCTAssertEqual(journal.unreadCount, EventJournal.capacity)
        XCTAssertEqual(journal.unreadEventIDs, Set(journal.events.map(\.id)))
        let restored = try JSONDecoder().decode(EventJournal.self, from: JSONEncoder().encode(journal))
        XCTAssertEqual(restored, journal)
    }

    func testOldJournalIsReadAndRetainsItsEvents() throws {
        struct OldJournal: Encodable { let events: [ActivityEvent] }
        let events = [ActivityEvent(title: "Existing")]
        let restored = try JSONDecoder().decode(EventJournal.self, from: JSONEncoder().encode(OldJournal(events: events)))
        XCTAssertEqual(restored.events, events)
        XCTAssertEqual(restored.unreadCount, 0)
    }

    func testDecodedOrphanIDsAreRemovedAndDuplicateRecordsDoNotDoubleCount() throws {
        struct StoredJournal: Encodable { let events: [ActivityEvent]; let unreadEventIDs: Set<UUID> }
        let event = ActivityEvent(title: "Existing")
        let stored = StoredJournal(events: [event], unreadEventIDs: [event.id, UUID()])
        var restored = try JSONDecoder().decode(EventJournal.self, from: JSONEncoder().encode(stored))
        XCTAssertEqual(restored.unreadCount, 1)
        restored.record(event)
        XCTAssertEqual(restored.events, [event])
        XCTAssertEqual(restored.unreadCount, 1)
    }
}
