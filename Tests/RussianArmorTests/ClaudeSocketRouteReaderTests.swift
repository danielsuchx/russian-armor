import ArmorCore
import Darwin
import Foundation
import XCTest
@testable import RussianArmor

final class ClaudeSocketRouteReaderTests: XCTestCase {
    func testKernelRouteLookupForLoopbackUsesRealRoutingSocketWithoutInternetTraffic() {
        XCTAssertEqual(SystemRouteLookup.interface(to: .init(address: "127.0.0.1", port: 0, version: .v4)), "lo0")
        XCTAssertEqual(SystemRouteLookup.interface(to: .init(address: "::1", port: 0, version: .v6)), "lo0")
        XCTAssertNil(SystemRouteLookup.interface(to: .init(address: "not-an-address", port: 0, version: .v4)))
    }

    func testTargetedScanReadsRealOwnSocketsAndTheirLocalRoute() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(listener, 0)
        guard listener >= 0 else { return }
        defer { Darwin.close(listener) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(bound, 0)
        XCTAssertEqual(listen(listener, 1), 0)
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &size) }
        }, 0)
        let client = socket(AF_INET, SOCK_STREAM, 0)
        guard client >= 0 else { return XCTFail("Cannot create test socket") }
        defer { Darwin.close(client) }
        XCTAssertEqual(withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }, 0)
        let identity = try XCTUnwrap(ProtectedProcessCatalog.identity(for: getpid()))
        let target = TrafficProcess.ID(pid: identity.pid, startSeconds: identity.startSeconds, startMicroseconds: identity.startMicroseconds)
        let snapshot = try ClaudeSocketRouteReader.read(identities: [target])
        let route = try XCTUnwrap(snapshot.routes.first { $0.connection.remote.port == UInt16(bigEndian: address.sin_port) })
        XCTAssertEqual(route.connection.process.id, target)
        XCTAssertEqual(route.connection.remote.address, "127.0.0.1")
        XCTAssertEqual(route.routeInterface, "lo0")
        XCTAssertTrue(route.sourceInterfaces.contains("lo0"))
        XCTAssertEqual(route.path, .localPeer)
        XCTAssertTrue(snapshot.routes.allSatisfy { $0.connection.process.id == target })
    }

    func testRoutingReplyMustMatchRequestAndHaveUsableInterface() {
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size)
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_pid = 100
        header.rtm_seq = 7
        header.rtm_index = 3
        header.rtm_flags = RTF_UP
        func decode(_ value: rt_msghdr) -> UInt16? {
            var copy = value
            let bytes = withUnsafeBytes(of: &copy) { Array($0) }
            return SystemRouteLookup.responseInterfaceIndex(bytes, pid: 100, sequence: 7)
        }
        XCTAssertEqual(decode(header), 3)
        header.rtm_seq = 8
        XCTAssertNil(decode(header))
        header.rtm_seq = 7
        header.rtm_pid = 101
        XCTAssertNil(decode(header))
        header.rtm_pid = 100
        header.rtm_flags |= RTF_BLACKHOLE
        XCTAssertNil(decode(header))
        header.rtm_flags = RTF_UP
        header.rtm_errno = ESRCH
        XCTAssertNil(decode(header))
        header.rtm_errno = 0
        header.rtm_msglen += 1
        XCTAssertNil(decode(header))
        XCTAssertNil(SystemRouteLookup.responseInterfaceIndex([0, 1, 2], pid: 100, sequence: 7))
    }

    func testEmptyTargetSetNeverFallsBackToAllUserProcesses() throws {
        let snapshot = try ClaudeSocketRouteReader.read(identities: [])
        XCTAssertTrue(snapshot.routes.isEmpty)
        XCTAssertFalse(snapshot.isPartial)
        let sockets = try SocketTrafficReader.read(identities: [])
        XCTAssertEqual(sockets.inspectedProcesses, 0)
    }

    func testReusedPIDCannotAttributeSocketsToAnOldIdentity() {
        let identity = TrafficProcess.ID(pid: getpid(), startSeconds: 0, startMicroseconds: 0)
        XCTAssertThrowsError(try SocketTrafficReader.read(identities: [identity]))
    }
}
