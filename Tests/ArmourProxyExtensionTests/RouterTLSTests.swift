import CryptoKit
import Foundation
import Security
import XCTest
@testable import ArmourProxyExtension

final class RouterTLSTests: XCTestCase {
    private static let certificate = Result { try makeCertificate() }
    private static let wrongSANCertificate = Result { try makeCertificate(serverName: "attacker.router") }

    private static func makeCertificate(serverName: String = "russian-armour.router") throws -> SecCertificate {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("RussianArmour.TLSFixture.\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = directory.appendingPathComponent("openssl.cnf")
        try """
        [req]
        distinguished_name=dn
        x509_extensions=server
        prompt=no
        [dn]
        CN=\(serverName)
        [server]
        subjectAltName=DNS:\(serverName)
        basicConstraints=critical,CA:FALSE
        keyUsage=critical,digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        # Unreachable AIA is deliberate: the verifier must disable fetching.
        authorityInfoAccess=caIssuers;URI:http://192.0.2.1/never-fetch.der
        """.write(to: config, atomically: true, encoding: .utf8)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                             "-config", config.path, "-keyout", directory.appendingPathComponent("key.pem").path,
                             "-outform", "DER", "-out", directory.appendingPathComponent("certificate.der").path]
        let diagnostics = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = diagnostics
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "RouterTLSTests.fixture", code: Int(process.terminationStatus))
        }
        let bytes = try Data(contentsOf: directory.appendingPathComponent("certificate.der"))
        guard let certificate = SecCertificateCreateWithData(nil, bytes as CFData) else {
            throw NSError(domain: "RouterTLSTests.fixture", code: 1)
        }
        return certificate
    }

    private func fixture() throws -> (SecTrust, Data) {
        let certificate = try Self.certificate.get()
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(certificate,
                       SecPolicyCreateSSL(true, "russian-armour.router" as CFString), &trust), errSecSuccess)
        return (try XCTUnwrap(trust), Data(SHA256.hash(data: SecCertificateCopyData(certificate) as Data)))
    }

    func testPinnedSelfSignedRouterCertificatePassesWithCorrectSANAndCurrentDate() throws {
        let (trust, pin) = try fixture()
        XCTAssertTrue(RouterTLSVerifier.validate(trust, certificateSHA256: pin, serverName: "russian-armour.router"))
    }

    func testAnotherCertificatePinIsRejected() throws {
        let (trust, pin) = try fixture()
        var wrong = pin
        wrong[wrong.startIndex] ^= 0xff
        XCTAssertFalse(RouterTLSVerifier.validate(trust, certificateSHA256: wrong, serverName: "russian-armour.router"))
    }

    func testWrongCertificateSANIsRejectedEvenWithExactCertificatePin() throws {
        let certificate = try Self.wrongSANCertificate.get()
        var object: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(certificate,
                       SecPolicyCreateSSL(true, "russian-armour.router" as CFString), &object), errSecSuccess)
        let trust = try XCTUnwrap(object)
        let pin = Data(SHA256.hash(data: SecCertificateCopyData(certificate) as Data))
        XCTAssertFalse(RouterTLSVerifier.validate(trust, certificateSHA256: pin, serverName: "russian-armour.router"))
    }

    func testExpiredVerificationDateIsRejectedEvenForPinnedSelfSignedAnchor() throws {
        let (trust, pin) = try fixture()
        XCTAssertFalse(RouterTLSVerifier.validate(trust, certificateSHA256: pin,
            serverName: "russian-armour.router", at: Date().addingTimeInterval(7 * 86_400)))
    }

    func testNotYetValidVerificationDateIsRejected() throws {
        let (trust, pin) = try fixture()
        XCTAssertFalse(RouterTLSVerifier.validate(trust, certificateSHA256: pin,
            serverName: "russian-armour.router", at: Date().addingTimeInterval(-7 * 86_400)))
    }

    func testTrustNetworkRetrievalIsDisabledBeforeEvaluationAndOnPinRejection() throws {
        for correctPin in [true, false] {
            let (trust, pin) = try fixture()
            XCTAssertEqual(SecTrustSetNetworkFetchAllowed(trust, true), errSecSuccess)
            _ = RouterTLSVerifier.validate(trust, certificateSHA256: correctPin ? pin : Data(repeating: 0, count: 32),
                                           serverName: "russian-armour.router")
            var allowed = DarwinBoolean(true)
            XCTAssertEqual(SecTrustGetNetworkFetchAllowed(trust, &allowed), errSecSuccess)
            XCTAssertFalse(allowed.boolValue)
        }
    }
}
