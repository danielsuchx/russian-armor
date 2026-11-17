import ArmorCore
import ArmorTunnel
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class HappConnectionMonitorTests: XCTestCase {
    private let identity = TrafficProcess.ID(pid: 42, startSeconds: 100, startMicroseconds: 1)

    private func tunnel(team: String = "A6NW69KD84", signingID: String = "su.ffg.happ.tunnel") -> VerifiedTunnel {
        VerifiedTunnel(interface: "utun7", owner: .init(pid: identity.pid, startSeconds: identity.startSeconds,
            startMicroseconds: identity.startMicroseconds), teamID: team, signingID: signingID, sourceAddresses: [])
    }

    private func row(_ address: String, port: UInt16 = 443, state: String = "Установлено",
                     transport: TrafficTransport = .tcp, identity: TrafficProcess.ID? = nil) -> TrafficConnection {
        TrafficConnection(process: .init(id: identity ?? self.identity, name: "Happ"), socketGeneration: 1,
            descriptor: Int32(port), transport: transport, local: .init(address: "10.0.0.2", port: port, version: .v4),
            remote: .init(address: address, port: port, version: address.contains(":") ? .v6 : .v4), state: state)
    }

    private func snapshot(_ addresses: [String] = ["8.8.8.8", "1.1.1.1"], time: Double = 1,
                          partial: Bool = false) -> TrafficSnapshot {
        TrafficSnapshot(connections: addresses.map { row($0) }, capturedAt: Date(timeIntervalSince1970: time),
                        isTruncated: partial)
    }

    private func settle() async {
        for _ in 0..<40 { await Task.yield() }
    }

    func testCountsDistinctAddressesNotPortsProtocolsOrMappedAliases() {
        let rows = [row("8.8.8.8"), row("8.8.8.8", port: 8443), row("::ffff:8.8.8.8"),
                    row("8.8.8.8", port: 53, transport: .udp), row("1.1.1.1"),
                    row("2606:4700:4700::1111"), row("2606:4700:4700:0:0:0:0:1111")]
        XCTAssertEqual(HappConnectionMonitor.addressCount(snapshot: .init(connections: rows), tunnels: [tunnel()]), 3)
    }

    func testIgnoresLocalInvalidAndClosingPeers() {
        let addresses = ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1",
                         "100.64.0.1", "0.0.0.0", "224.0.0.1", "::", "::1", "fd00::1", "fe80::1",
                         "ff02::1", "::ffff:192.168.1.1", "invalid"]
        let rows = addresses.map { row($0) } + [row("8.8.8.8", state: "Time wait"), row("1.1.1.1", port: 0)]
        XCTAssertEqual(HappConnectionMonitor.addressCount(snapshot: .init(connections: rows), tunnels: [tunnel()]), 0)
    }

    func testDoesNotTrustProcessNameWrongSignatureOrReusedPID() {
        XCTAssertNil(HappConnectionMonitor.addressCount(snapshot: snapshot(), tunnels: []))
        XCTAssertNil(HappConnectionMonitor.addressCount(snapshot: snapshot(), tunnels: [tunnel(team: "OTHER")]))
        XCTAssertNil(HappConnectionMonitor.addressCount(snapshot: snapshot(), tunnels: [tunnel(signingID: "other.tunnel")]))
        let reused = TrafficProcess.ID(pid: 42, startSeconds: 101, startMicroseconds: 1)
        XCTAssertEqual(HappConnectionMonitor.addressCount(snapshot: .init(connections: [row("8.8.8.8", identity: reused)]),
                                                        tunnels: [tunnel()]), 0)
    }

    func testTwoSamplesEmitOnceAndCompleteSingleAddressRearms() async {
        let owner = tunnel()
        let monitor = HappConnectionMonitor(ownerReader: { [owner] })
        var counts: [Int] = []
        monitor.onMultipleAddresses = { counts.append($0) }
        monitor.receive(.observed(snapshot(time: 1)), recordsEvents: true)
        await settle()
        XCTAssertTrue(counts.isEmpty)
        monitor.receive(.observed(snapshot(time: 1)), recordsEvents: true)
        await settle()
        XCTAssertTrue(counts.isEmpty, "Repeated snapshot is not a second confirmation")
        for time in 2...4 {
            monitor.receive(.observed(snapshot(time: Double(time))), recordsEvents: true)
            await settle()
        }
        XCTAssertEqual(counts, [2])
        monitor.receive(.observed(snapshot(["8.8.8.8"], time: 5)), recordsEvents: true)
        await settle()
        for time in 6...7 {
            monitor.receive(.observed(snapshot(time: Double(time))), recordsEvents: true)
            await settle()
        }
        XCTAssertEqual(counts, [2, 2])
    }

    func testPartialFailureAndSleepDoNotRearmOrConfirmStaleSamples() async {
        let owner = tunnel()
        let monitor = HappConnectionMonitor(ownerReader: { [owner] })
        var events = 0
        monitor.onMultipleAddresses = { _ in events += 1 }
        monitor.receive(.observed(snapshot(time: 1)), recordsEvents: true)
        await settle()
        monitor.receive(.failed("Unavailable"), recordsEvents: true)
        monitor.receive(.observed(snapshot(time: 2)), recordsEvents: true)
        await settle()
        XCTAssertEqual(events, 0)
        monitor.receive(.observed(snapshot(time: 3, partial: true)), recordsEvents: true)
        await settle()
        XCTAssertEqual(events, 1, "A partial scan still provides a lower bound")
        monitor.receive(.observed(snapshot([], time: 4, partial: true)), recordsEvents: true)
        await settle()
        monitor.receive(.sleeping, recordsEvents: true)
        for time in 5...6 {
            monitor.receive(.observed(snapshot(time: Double(time))), recordsEvents: true)
            await settle()
        }
        XCTAssertEqual(events, 1)
    }

    func testDisabledRecordingAndOffNeverReadOwners() async {
        actor Reads {
            var count = 0
            func read() -> [VerifiedTunnel] { count += 1; return [] }
        }
        let reads = Reads()
        let monitor = HappConnectionMonitor(ownerReader: { await reads.read() })
        monitor.receive(.observed(snapshot()), recordsEvents: false)
        monitor.receive(.off, recordsEvents: true)
        await settle()
        let count = await reads.count
        XCTAssertEqual(count, 0)
    }

    func testLateOwnerResponseAfterStopIsDiscarded() async {
        let owner = tunnel()
        actor Pending {
            var continuation: CheckedContinuation<[VerifiedTunnel], Never>?
            func read() async -> [VerifiedTunnel] {
                await withCheckedContinuation { continuation = $0 }
            }
            func finish(_ owners: [VerifiedTunnel]) { continuation?.resume(returning: owners); continuation = nil }
        }
        let pending = Pending()
        let monitor = HappConnectionMonitor(ownerReader: { await pending.read() })
        var events = 0
        monitor.onMultipleAddresses = { _ in events += 1 }
        monitor.receive(.observed(snapshot(time: 1)), recordsEvents: true)
        await settle()
        monitor.receive(.off, recordsEvents: true)
        await pending.finish([owner])
        await settle()
        XCTAssertEqual(events, 0)
    }
}
