import Darwin
import Foundation

/// Framing errors deliberately contain no endpoint, username or password.
public enum SOCKS5Error: Error, Equatable, Sendable {
    case invalidCredentials
    case invalidDestination
    case invalidVersion
    case authenticationMethodRejected
    case authenticationRejected
    case connectionRejected(UInt8)
    case invalidReservedByte
    case unsupportedAddressType
    case invalidReplyAddress
}

/// A successfully parsed frame and any bytes belonging to the next frame or
/// application payload. Callers must retain `remainder` when advancing stages.
public struct SOCKS5Reply: Equatable, Sendable {
    public let consumedBytes: Int
    public let remainder: Data

    fileprivate init(bytes: Data, consumedBytes: Int) {
        self.consumedBytes = consumedBytes
        remainder = Data(bytes.dropFirst(consumedBytes))
    }
}

/// RFC 1928/1929 client framing only. No network operations, endpoint discovery
/// or VPN assertions. Incomplete reply frames return nil without consuming data.
/// Parsers inspect at most 262 bytes, independent of appended application data.
public enum SOCKS5Codec {
    /// Offer only RFC 1929 authentication. A server choosing no-auth is rejected.
    public static let methodGreeting = Data([0x05, 0x01, 0x02])
    public static let maximumConnectReplyLength = 262

    public static func authenticationRequest(username: String, password: String) throws -> Data {
        guard (1...255).contains(username.utf8.count), (1...255).contains(password.utf8.count) else {
            throw SOCKS5Error.invalidCredentials
        }
        let user = Data(username.utf8)
        let secret = Data(password.utf8)
        var request = Data([0x01, UInt8(user.count)])
        request.append(user)
        request.append(UInt8(secret.count))
        request.append(secret)
        return request
    }

    /// Hostnames stay in the CONNECT request for resolution at the SOCKS server.
    /// IP literals are sent in their binary address family; scoped IPv6 addresses
    /// and URL strings are not valid remote destinations.
    public static func connectRequest(host: String, port: UInt16) throws -> Data {
        let forbidden = CharacterSet.whitespacesAndNewlines
            .union(.controlCharacters)
            .union(CharacterSet(charactersIn: "/\\%[]@"))
        guard port != 0, !host.isEmpty,
              host.rangeOfCharacter(from: forbidden) == nil else {
            throw SOCKS5Error.invalidDestination
        }
        var request = Data([0x05, 0x01, 0x00])
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if inet_pton(AF_INET, host, &ipv4) == 1 {
            request.append(0x01)
            withUnsafeBytes(of: ipv4) { request.append(contentsOf: $0) }
        } else if inet_pton(AF_INET6, host, &ipv6) == 1 {
            request.append(0x04)
            withUnsafeBytes(of: ipv6) { request.append(contentsOf: $0) }
        } else {
            let encoded = Data(host.utf8)
            let isInvalidNumericAddress = host.allSatisfy { $0.isASCII && ($0.isNumber || $0 == ".") }
            guard (1...255).contains(encoded.count),
                  !host.contains(":"),
                  !isInvalidNumericAddress else {
                throw SOCKS5Error.invalidDestination
            }
            request.append(0x03)
            request.append(UInt8(encoded.count))
            request.append(encoded)
        }
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xff))
        return request
    }

    public static func parseMethodSelection(_ bytes: Data) throws -> SOCKS5Reply? {
        guard !bytes.isEmpty else { return nil }
        guard byte(bytes, 0) == 0x05 else { throw SOCKS5Error.invalidVersion }
        guard bytes.count >= 2 else { return nil }
        guard byte(bytes, 1) == 0x02 else { throw SOCKS5Error.authenticationMethodRejected }
        return SOCKS5Reply(bytes: bytes, consumedBytes: 2)
    }

    public static func parseAuthenticationReply(_ bytes: Data) throws -> SOCKS5Reply? {
        guard !bytes.isEmpty else { return nil }
        guard byte(bytes, 0) == 0x01 else { throw SOCKS5Error.invalidVersion }
        guard bytes.count >= 2 else { return nil }
        guard byte(bytes, 1) == 0x00 else { throw SOCKS5Error.authenticationRejected }
        return SOCKS5Reply(bytes: bytes, consumedBytes: 2)
    }

    public static func parseConnectReply(_ bytes: Data) throws -> SOCKS5Reply? {
        guard !bytes.isEmpty else { return nil }
        guard byte(bytes, 0) == 0x05 else { throw SOCKS5Error.invalidVersion }
        guard bytes.count >= 2 else { return nil }
        guard byte(bytes, 1) == 0x00 else { throw SOCKS5Error.connectionRejected(byte(bytes, 1)) }
        guard bytes.count >= 3 else { return nil }
        guard byte(bytes, 2) == 0x00 else { throw SOCKS5Error.invalidReservedByte }
        guard bytes.count >= 4 else { return nil }

        let length: Int
        switch byte(bytes, 3) {
        case 0x01:
            length = 10
        case 0x04:
            length = 22
        case 0x03:
            guard bytes.count >= 5 else { return nil }
            let addressLength = Int(byte(bytes, 4))
            guard addressLength > 0 else { throw SOCKS5Error.invalidReplyAddress }
            length = 7 + addressLength
            if bytes.count >= length {
                let address = bytes.dropFirst(5).prefix(addressLength)
                guard let host = String(data: Data(address), encoding: .utf8),
                      host.rangeOfCharacter(from: .controlCharacters) == nil else {
                    throw SOCKS5Error.invalidReplyAddress
                }
            }
        default:
            throw SOCKS5Error.unsupportedAddressType
        }
        guard bytes.count >= length else { return nil }
        return SOCKS5Reply(bytes: bytes, consumedBytes: length)
    }

    private static func byte(_ bytes: Data, _ offset: Int) -> UInt8 {
        bytes[bytes.startIndex + offset]
    }
}
