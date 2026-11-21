import CryptoKit
import Foundation
import XCTest
@testable import RussianArmor

final class UpdateSignatureTests: XCTestCase {
    private func update(version: String = "0.3.0", size: Int64 = 4) -> GitHubUpdate {
        GitHubUpdate(version: ReleaseVersion(version)!, url: URL(string: "https://github.com/danielsuchx/russian-armor/releases/download/v\(version)/Russian-Armor.dmg")!, size: size, sha256: String(repeating: "a", count: 64))
    }
    func testReleaseSignatureBindsVersionSizeAndHashAndRejectsOtherPublisher() throws {
        let key = Curve25519.Signing.PrivateKey()
        let release = update()
        let signature = try key.signature(for: UpdateSignature.payload(for: release)).base64EncodedData()
        XCTAssertNoThrow(try UpdateSignature.verify(signature, update: release, publicKey: key.publicKey.rawRepresentation))
        XCTAssertThrowsError(try UpdateSignature.verify(signature, update: update(version: "0.3.1"), publicKey: key.publicKey.rawRepresentation))
        XCTAssertThrowsError(try UpdateSignature.verify(signature, update: update(size: 5), publicKey: key.publicKey.rawRepresentation))
        XCTAssertThrowsError(try UpdateSignature.verify(signature, update: release, publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation))
        XCTAssertThrowsError(try UpdateSignature.verify(Data("unsigned".utf8), update: release, publicKey: key.publicKey.rawRepresentation))
    }

    func testRollbackHistoryRequiresOlderStableCanonicalSignedRelease() throws {
        let hash = String(repeating: "a", count: 64)
        func row(_ version: String, signed: Bool = true, draft: Bool = false, signatureHost: String = "https://github.com/danielsuchx/russian-armor") -> [String: Any] {
            let base = "https://github.com/danielsuchx/russian-armor/releases/download/v\(version)/"
            var assets: [[String: Any]] = [["name": "Russian-Armor.dmg", "size": 4, "browser_download_url": base + "Russian-Armor.dmg", "digest": "sha256:" + hash]]
            if signed { assets.append(["name": "Russian-Armor.dmg.sig", "size": 89, "browser_download_url": signatureHost + "/releases/download/v\(version)/Russian-Armor.dmg.sig"]) }
            return ["tag_name": "v" + version, "draft": draft, "prerelease": false, "assets": assets]
        }
        let data = try JSONSerialization.data(withJSONObject: [row("0.3.1"), row("0.3.0"), row("0.2.9"),
            row("0.2.8", signed: false), row("0.2.7", draft: true), row("0.2.6", signatureHost: "https://example.org")])
        let history = try GitHubUpdate.rollbackVersions(in: data, before: ReleaseVersion("0.3.0")!)
        XCTAssertEqual(history.map(\.version.description), ["0.2.9"])
    }
}
