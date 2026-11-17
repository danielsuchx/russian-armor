@testable import ArmorTunnel
import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

final class TunnelCheckTests: XCTestCase {
    private func response(_ headers: String, _ body: String) -> Data {
        Data("HTTP/1.1 200 OK\r\n\(headers)\r\n\r\n\(body)".utf8)
    }

    func testHTTPFramingHandlesPartialLengthAndChunkedBodies() throws {
        XCTAssertNil(try TunnelHTTPResponse.body(response("Content-Length: 5", "abc"), complete: false))
        XCTAssertThrowsError(try TunnelHTTPResponse.body(response("Content-Length: 5", "abc"), complete: true))
        XCTAssertEqual(try TunnelHTTPResponse.body(response("Content-Length: 3", "abc"), complete: false), Data("abc".utf8))
        XCTAssertEqual(try TunnelHTTPResponse.body(response("Transfer-Encoding: chunked", "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"), complete: true), Data("abcde".utf8))
        XCTAssertNil(try TunnelHTTPResponse.body(response("Transfer-Encoding: chunked", "3\r\nab"), complete: false))
        XCTAssertThrowsError(try TunnelHTTPResponse.body(response("Transfer-Encoding: chunked", "\r\n"), complete: true))
        XCTAssertEqual(try TunnelHTTPResponse.body(response("Content-Type: application/json", "{}"), complete: true), Data("{}".utf8))
    }

    func testRejectsRedirectEncodingOversizeAndAmbiguousFraming() {
        for payload in [Data("HTTP/1.1 302 Found\r\nLocation: https://other.example\r\n\r\n".utf8),
                        response("Content-Length: 999999", ""), response("Content-Encoding: gzip", "abc"),
                        response("Content-Length: 3\r\nContent-Length: 3", "abc"),
                        response("Transfer-Encoding: chunked\r\nContent-Length: 0", "0\r\n\r\n"),
                        response("Transfer-Encoding: chunked", "ffffffff\r\n"),
                        response("Content-Length: 1", "abc")] {
            XCTAssertThrowsError(try TunnelHTTPResponse.body(payload, complete: true))
        }
    }

    func testBoundHTTPPreservesRateLimitRetryAfter() {
        let started = Date()
        let response = Data("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 180\r\nContent-Length: 0\r\n\r\n".utf8)
        XCTAssertThrowsError(try TunnelHTTPResponse.body(response, complete: true)) {
            guard case EgressError.rateLimited(let until) = $0 else { return XCTFail("Missing Retry-After") }
            XCTAssertEqual(until.timeIntervalSince(started), 180, accuracy: 1)
        }
    }

    func testTunnelSelectionMustBeUnambiguousAndPinnedToSignedOwner() throws {
        let identity = ProtectedProcessIdentity(pid: 42, startSeconds: 1, startMicroseconds: 0)
        let first = VerifiedTunnel(interface: "utun4", owner: identity, teamID: "TEAM", signingID: "vpn.one", sourceAddresses: ["10.1.0.2"])
        let second = VerifiedTunnel(interface: "utun5", owner: identity, teamID: "OTHER", signingID: "vpn.two", sourceAddresses: ["10.2.0.2"])
        XCTAssertEqual(try TunnelOwnershipReader.select([first], ownerKey: nil), first)
        XCTAssertThrowsError(try TunnelOwnershipReader.select([], ownerKey: nil))
        XCTAssertThrowsError(try TunnelOwnershipReader.select([first, second], ownerKey: nil))
        XCTAssertEqual(try TunnelOwnershipReader.select([first, second], ownerKey: first.ownerKey), first)
        XCTAssertThrowsError(try TunnelOwnershipReader.select([second], ownerKey: first.ownerKey))
        XCTAssertEqual(TunnelOwnershipReader.interface(controlName: "com.apple.net.utun_control", unit: 5), "utun4")
        XCTAssertNil(TunnelOwnershipReader.interface(controlName: "com.apple.net.utun_control", unit: 0))
        XCTAssertNil(TunnelOwnershipReader.interface(controlName: "other", unit: 5))
    }
}
