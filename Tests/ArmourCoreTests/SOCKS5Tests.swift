import Foundation
import XCTest
@testable import ArmourCore

final class SOCKS5Tests: XCTestCase {
    func testOffersPasswordAuthenticationOnlyAndRejectsDowngrade() throws {
        XCTAssertEqual(SOCKS5Codec.methodGreeting, Data([5, 1, 2]))
        for method: UInt8 in [0, 1, 3, 255] {
            XCTAssertThrowsError(try SOCKS5Codec.parseMethodSelection(Data([5, method]))) {
                XCTAssertEqual($0 as? SOCKS5Error, .authenticationMethodRejected)
            }
        }
        XCTAssertEqual(try SOCKS5Codec.parseMethodSelection(Data([5, 2, 1, 0]))?.remainder, Data([1, 0]))
    }

    func testAuthenticationUsesUTF8ByteLengthsAndEnforcesBounds() throws {
        XCTAssertEqual(try SOCKS5Codec.authenticationRequest(username: "я", password: "ё"),
                       Data([1, 2, 0xd1, 0x8f, 2, 0xd1, 0x91]))
        let maximum = String(repeating: "a", count: 255)
        XCTAssertEqual(try SOCKS5Codec.authenticationRequest(username: maximum, password: maximum).count, 513)
        for (user, password) in [("", "secret"), ("user", ""), (maximum + "a", "secret"),
                                 ("user", maximum + "a"), (String(repeating: "я", count: 128), "secret")] {
            XCTAssertThrowsError(try SOCKS5Codec.authenticationRequest(username: user, password: password)) {
                XCTAssertEqual($0 as? SOCKS5Error, .invalidCredentials)
            }
        }
    }

    func testEncodesDomainWithoutResolvingItLocally() throws {
        var expected = Data([5, 1, 0, 3, 11])
        expected.append(Data("example.com".utf8))
        expected.append(contentsOf: [1, 187])
        XCTAssertEqual(try SOCKS5Codec.connectRequest(host: "example.com", port: 443), expected)
        let maximum = String(repeating: "a", count: 255)
        XCTAssertEqual(try SOCKS5Codec.connectRequest(host: maximum, port: 65535).count, 262)
        XCTAssertThrowsError(try SOCKS5Codec.connectRequest(host: maximum + "a", port: 443))
        XCTAssertThrowsError(try SOCKS5Codec.connectRequest(host: String(repeating: "я", count: 128), port: 443))
    }

    func testEncodesBothIPFamiliesAsBinaryAndNetworkByteOrderPort() throws {
        XCTAssertEqual(try SOCKS5Codec.connectRequest(host: "203.0.113.8", port: 8443),
                       Data([5, 1, 0, 1, 203, 0, 113, 8, 32, 251]))
        XCTAssertEqual(try SOCKS5Codec.connectRequest(host: "2001:db8::1", port: 443),
                       Data([5, 1, 0, 4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187]))
    }

    func testRejectsInvalidDestinationsWithoutInterpolatingCredentials() {
        for host in ["", "example.com\u{0000}suffix", "example.com\n", "example.com path", "https://example.com",
                     "example.com:443", "[2001:db8::1]", "fe80::1%en0", "999.1.1.1", "user@example.com"] {
            XCTAssertThrowsError(try SOCKS5Codec.connectRequest(host: host, port: 443), "Accepted \(host.debugDescription)") {
                XCTAssertEqual($0 as? SOCKS5Error, .invalidDestination)
            }
        }
        XCTAssertThrowsError(try SOCKS5Codec.connectRequest(host: "example.com", port: 0))
    }

    func testEveryTruncationWaitsAndEveryReplyPreservesFollowingPayload() throws {
        let frames = [
            Data([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            Data([5, 0, 0, 4] + Array(repeating: UInt8(0), count: 18)),
            Data([5, 0, 0, 3, 3]) + Data("abc".utf8) + Data([0, 1])
        ]
        let payload = Data([0x16, 3, 1, 0, 5, 0xff])
        for frame in frames {
            for length in 0..<frame.count {
                XCTAssertNil(try SOCKS5Codec.parseConnectReply(Data(frame.prefix(length))), "Prefix \(length)")
            }
            let parsed = try XCTUnwrap(SOCKS5Codec.parseConnectReply(frame + payload))
            XCTAssertEqual(parsed.consumedBytes, frame.count)
            XCTAssertEqual(parsed.remainder, payload)
        }
        for length in 0..<2 {
            XCTAssertNil(try SOCKS5Codec.parseMethodSelection(Data(Data([5, 2]).prefix(length))))
            XCTAssertNil(try SOCKS5Codec.parseAuthenticationReply(Data(Data([1, 0]).prefix(length))))
        }
        XCTAssertEqual(try SOCKS5Codec.parseAuthenticationReply(Data([1, 0]) + payload)?.remainder, payload)
    }

    func testMaximumDomainReplyDoesNotMistakeApplicationDataForOversizedFrame() throws {
        let frame = Data([5, 0, 0, 3, 255]) + Data(repeating: 97, count: 255) + Data([0, 1])
        XCTAssertEqual(frame.count, SOCKS5Codec.maximumConnectReplyLength)
        let payload = Data(repeating: 0xff, count: 65536)
        let reply = try XCTUnwrap(SOCKS5Codec.parseConnectReply(frame + payload))
        XCTAssertEqual(reply.consumedBytes, 262)
        XCTAssertEqual(reply.remainder, payload)
    }

    func testMalformedRepliesAndAuthenticationFailureAreRejectedEarly() {
        let malformed: [(Data, SOCKS5Error)] = [
            (Data([4]), .invalidVersion),
            (Data([5, 5]), .connectionRejected(5)),
            (Data([5, 0, 1]), .invalidReservedByte),
            (Data([5, 0, 0, 9]), .unsupportedAddressType),
            (Data([5, 0, 0, 3, 0]), .invalidReplyAddress),
            (Data([5, 0, 0, 3, 1, 0xff, 0, 1]), .invalidReplyAddress),
            (Data([5, 0, 0, 3, 1, 0, 0, 1]), .invalidReplyAddress)
        ]
        for (bytes, expected) in malformed {
            XCTAssertThrowsError(try SOCKS5Codec.parseConnectReply(bytes)) {
                XCTAssertEqual($0 as? SOCKS5Error, expected)
            }
        }
        XCTAssertThrowsError(try SOCKS5Codec.parseAuthenticationReply(Data([1, 1]))) {
            XCTAssertEqual($0 as? SOCKS5Error, .authenticationRejected)
        }
        XCTAssertThrowsError(try SOCKS5Codec.parseMethodSelection(Data([4]))) {
            XCTAssertEqual($0 as? SOCKS5Error, .invalidVersion)
        }
        XCTAssertThrowsError(try SOCKS5Codec.parseAuthenticationReply(Data([5]))) {
            XCTAssertEqual($0 as? SOCKS5Error, .invalidVersion)
        }
    }

    func testDataWithNonzeroStartIndexParsesWithoutOffsetAssumptions() throws {
        var bytes = Data([0xff, 0xff, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 99])
        bytes.removeFirst(2)
        let reply = try XCTUnwrap(SOCKS5Codec.parseConnectReply(bytes))
        XCTAssertEqual(reply.consumedBytes, 10)
        XCTAssertEqual(reply.remainder, Data([99]))
    }
}
