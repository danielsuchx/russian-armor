import ArmourCore
import Darwin
import XCTest
@testable import RussianArmour

final class SocketTrafficReaderTests: XCTestCase {
    private let process = TrafficProcess(id: .init(pid: 42, startSeconds: 100, startMicroseconds: 1), name: "Fixture")

    private func ipv4(tcp: Bool = true) -> socket_fdinfo {
        var result = socket_fdinfo()
        result.psi.soi_family = AF_INET
        result.psi.soi_type = tcp ? SOCK_STREAM : SOCK_DGRAM
        result.psi.soi_protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP
        result.psi.soi_kind = Int32(tcp ? SOCKINFO_TCP : SOCKINFO_IN)
        var inet = in_sockinfo()
        inet.insi_vflag = UInt8(INI_IPV4)
        inet.insi_gencnt = 321
        inet.insi_fport = Int32(UInt16(443).bigEndian)
        inet.insi_lport = Int32(UInt16(51000).bigEndian)
        inet_pton(AF_INET, "203.0.113.7", &inet.insi_faddr.ina_46.i46a_addr4)
        inet_pton(AF_INET, "192.0.2.5", &inet.insi_laddr.ina_46.i46a_addr4)
        if tcp {
            result.psi.soi_proto.pri_tcp.tcpsi_ini = inet
            result.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_ESTABLISHED
        } else { result.psi.soi_proto.pri_in = inet }
        return result
    }

    func testTCPIPv4AndPortByteOrder() throws {
        let row = try XCTUnwrap(SocketTrafficReader.decode(ipv4(), process: process, descriptor: 7))
        XCTAssertEqual(row.remote.title, "203.0.113.7:443")
        XCTAssertEqual(row.local.title, "192.0.2.5:51000")
        XCTAssertEqual(row.transport, .tcp)
        XCTAssertEqual(row.state, "Установлено")
        XCTAssertEqual(row.process, process)
    }

    func testIPv6AndMappedIPv4() throws {
        var info = ipv4()
        info.psi.soi_family = AF_INET6
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = UInt8(INI_IPV6)
        inet_pton(AF_INET6, "2001:db8::7", &info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6)
        inet_pton(AF_INET6, "2001:db8::5", &info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6)
        let row = try XCTUnwrap(SocketTrafficReader.decode(info, process: process, descriptor: 7))
        XCTAssertEqual(row.remote.title, "[2001:db8::7]:443")
        XCTAssertEqual(row.remote.version, .v6)
        var mapped = ipv4()
        mapped.psi.soi_family = AF_INET6
        let ipv4Row = try XCTUnwrap(SocketTrafficReader.decode(mapped, process: process, descriptor: 7))
        XCTAssertEqual(ipv4Row.remote.version, .v4)
    }

    func testOnlyUDPWithAPeerIsIncluded() throws {
        var info = ipv4(tcp: false)
        let row = try XCTUnwrap(SocketTrafficReader.decode(info, process: process, descriptor: 7))
        XCTAssertEqual(row.transport, .udp)
        XCTAssertEqual(row.state, "Задан peer")
        info.psi.soi_proto.pri_in.insi_fport = 0
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: 7))
    }

    func testListenersClosedUnixAndUnknownAddressesAreNotConnections() {
        var info = ipv4()
        info.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_LISTEN
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: 7))
        info.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_CLOSED
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: 7))
        info = ipv4()
        info.psi.soi_family = AF_UNIX
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: 7))
        info = ipv4()
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = 0
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: 7))
        info = ipv4()
        inet_pton(AF_INET, "0.0.0.0", &info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4)
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: 7))
    }

    func testOwnershipChecksRealEffectiveAndSavedUID() {
        var info = proc_bsdinfo()
        info.pbi_uid = 501
        info.pbi_ruid = 501
        info.pbi_svuid = 501
        XCTAssertTrue(SocketTrafficReader.belongsToUser(info, 501))
        XCTAssertFalse(SocketTrafficReader.belongsToUser(info, 502))
        info.pbi_svuid = 0
        XCTAssertFalse(SocketTrafficReader.belongsToUser(info, 501))
        info.pbi_svuid = 501
        info.pbi_ruid = 502
        XCTAssertFalse(SocketTrafficReader.belongsToUser(info, 501))
    }

    func testLibprocReadsOnlyAnOwnUnconnectedFixtureSocket() throws {
        // No bind, connect, send, packet capture or enumeration of other processes.
        let fd = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        guard fd >= 0 else { return }
        defer { Darwin.close(fd) }
        var info = socket_fdinfo()
        let received = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &info, Int32(MemoryLayout<socket_fdinfo>.size))
        XCTAssertEqual(received, Int32(MemoryLayout<socket_fdinfo>.size))
        XCTAssertEqual(info.psi.soi_protocol, IPPROTO_UDP)
        XCTAssertNil(SocketTrafficReader.decode(info, process: process, descriptor: fd))
    }
}
