import ArmorCore
import Foundation
import XCTest

final class ClaudeRoutesTests: XCTestCase {
    private func route(source: String = "10.8.0.2", peer: String = "203.0.113.8", version: TrafficIPVersion = .v4,
                       interfaces: [String] = ["utun4"], destination: String? = "utun4") -> ClaudeConnectionRoute {
        let process = TrafficProcess(id: .init(pid: 42, startSeconds: 1, startMicroseconds: 2), name: "claude")
        let connection = TrafficConnection(process: process, socketGeneration: 1, descriptor: 5, transport: .tcp,
                                           local: .init(address: source, port: 50000, version: version),
                                           remote: .init(address: peer, port: 443, version: version), state: "Установлено")
        return ClaudeConnectionRoute(connection: connection, sourceInterfaces: interfaces, routeInterface: destination)
    }

    func testTunnelNeedsBothSourceInterfaceAndDestinationRoute() {
        XCTAssertEqual(route().path, .tunnel(interface: "utun4"))
        let oldSocket = route(source: "192.168.1.2", interfaces: ["en0"])
        XCTAssertEqual(oldSocket.path, .outsideTunnel(interface: "utun4"))
        XCTAssertNotNil(ClaudeRouteSnapshot(routes: [oldSocket]).pauseReason(vpnLocation: .thisMac))
        XCTAssertEqual(route(interfaces: []).path, .unknown)
        XCTAssertEqual(route(destination: nil).path, .unknown)
        XCTAssertEqual(route(interfaces: ["utun5"]).path, .unknown)
        XCTAssertEqual(route(interfaces: ["utun4", "utun5"]).path, .unknown)
    }

    func testOneUnsafeSocketInvalidatesOtherwiseTunnelledSnapshot() {
        let direct = route(interfaces: ["en0"], destination: "en0")
        let snapshot = ClaudeRouteSnapshot(routes: [route(), direct])
        XCTAssertNotNil(snapshot.pauseReason(vpnLocation: .thisMac))
        XCTAssertNil(snapshot.pauseReason(vpnLocation: .router))
        XCTAssertNil(snapshot.pauseReason(vpnLocation: .unspecified))
    }

    func testIPv6DirectRouteIsNotHiddenByIPv4Tunnel() {
        let ipv6 = route(source: "2001:db8::2", peer: "2001:db8::8", version: .v6,
                         interfaces: ["en0"], destination: "en0")
        XCTAssertNotNil(ClaudeRouteSnapshot(routes: [route(), ipv6]).pauseReason(vpnLocation: .thisMac))
    }

    func testLocalPeersAreExplicitlyUnverifiedNotMislabelledAsTunnelled() {
        for peer in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.2", "100.64.0.1"] {
            let local = route(peer: peer, interfaces: ["lo0"], destination: nil)
            XCTAssertEqual(local.path, .localPeer, peer)
            XCTAssertNil(ClaudeRouteSnapshot(routes: [local]).pauseReason(vpnLocation: .thisMac))
            XCTAssertTrue(local.title.contains("неизвестен"))
        }
        for peer in ["::1", "fe80::1", "fd00::1", "fc00::1", "::ffff:127.0.0.1"] {
            XCTAssertEqual(route(peer: peer, version: .v6, destination: nil).path, .localPeer, peer)
        }
        XCTAssertEqual(route(peer: "172.32.0.1", destination: nil).path, .unknown)
    }

    func testUnknownAndPartialSnapshotsPauseRegardlessOfVPNLocation() {
        for location in VPNLocation.allCases {
            XCTAssertNotNil(ClaudeRouteSnapshot(routes: [route(destination: nil)]).pauseReason(vpnLocation: location))
            XCTAssertNotNil(ClaudeRouteSnapshot(routes: [route()], isPartial: true).pauseReason(vpnLocation: location))
        }
        XCTAssertNil(ClaudeRouteSnapshot(routes: []).pauseReason(vpnLocation: .thisMac))
    }

    func testAmbiguousSourceAndTunnelLikeNamesDoNotPass() {
        XCTAssertNotNil(ClaudeRouteSnapshot(routes: [route(interfaces: ["utun4", "en0"])]).pauseReason(vpnLocation: .thisMac))
        XCTAssertEqual(route(interfaces: ["utunfake"], destination: "utunfake").path, .outsideTunnel(interface: "utunfake"))
    }
}
