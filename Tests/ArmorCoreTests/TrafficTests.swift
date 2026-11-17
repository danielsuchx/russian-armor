import ArmorCore
import XCTest

final class TrafficTests: XCTestCase {
    private func row(pid: Int32 = 42, start: UInt64 = 100, generation: UInt64 = 1, descriptor: Int32 = 7,
                     remote: String = "203.0.113.7") -> TrafficConnection {
        TrafficConnection(process: .init(id: .init(pid: pid, startSeconds: start, startMicroseconds: 1), name: "Fixture"),
                          socketGeneration: generation, descriptor: descriptor, transport: .tcp,
                          local: .init(address: "192.0.2.5", port: 51000, version: .v4),
                          remote: .init(address: remote, port: 443, version: .v4), state: "Установлено")
    }

    func testDuplicatedFileDescriptorsDoNotDoubleCountASocket() {
        let snapshot = TrafficSnapshot(connections: [row(descriptor: 7), row(descriptor: 8)])
        XCTAssertEqual(snapshot.connections.count, 1)
        let withoutGeneration = TrafficSnapshot(connections: [row(generation: 0, descriptor: 7), row(generation: 0, descriptor: 8)])
        XCTAssertEqual(withoutGeneration.connections.count, 2)
    }

    func testPIDAndSocketReuseHaveDifferentIdentities() {
        XCTAssertNotEqual(row().id, row(start: 101).id)
        XCTAssertNotEqual(row().id, row(generation: 2).id)
        XCTAssertNotEqual(row().id, row(remote: "203.0.113.8").id)
    }

    func testSnapshotIsBoundedAndExplicitlyPartial() {
        let snapshot = TrafficSnapshot(connections: (0..<1005).map { row(generation: UInt64($0 + 1)) })
        XCTAssertEqual(snapshot.connections.count, TrafficSnapshot.capacity)
        XCTAssertTrue(snapshot.isTruncated)
        XCTAssertTrue(snapshot.isPartial)
        XCTAssertTrue(TrafficSnapshot(connections: [], inaccessibleProcesses: 1).isPartial)
        XCTAssertTrue(TrafficSnapshot(connections: [], inaccessibleSockets: 1).isPartial)
    }

    func testIPv6EndpointUsesBracketsAndLoopbackIsExplicit() {
        XCTAssertEqual(TrafficEndpoint(address: "2001:db8::7", port: 443, version: .v6).title, "[2001:db8::7]:443")
        XCTAssertTrue(TrafficEndpoint(address: "127.1.2.3", port: 80, version: .v4).isLoopback)
        XCTAssertTrue(TrafficEndpoint(address: "::1", port: 80, version: .v6).isLoopback)
        XCTAssertFalse(TrafficEndpoint(address: "192.0.2.5", port: 80, version: .v4).isLoopback)
    }

    func testProcessLabelsCannotInjectControlCharacters() {
        let process = TrafficProcess(id: .init(pid: 1, startSeconds: 0, startMicroseconds: 0), name: "Bad\n\t\0\u{202e}Name")
        XCTAssertEqual(process.name, "BadName")
    }
}
