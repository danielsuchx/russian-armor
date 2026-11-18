import CryptoKit
import Foundation
import XCTest
@testable import RussianArmor

final class GitHubUpdateTests: XCTestCase {
    private let base = "https://github.com/danielsuchx/russian-armor/releases/download/"
    private let fixtureHash = String(repeating: "a", count: 64)
    private var current: ReleaseVersion { ReleaseVersion("0.2.2")! }

    private func release(tag: String = "v0.2.10", url: String? = nil, digest: String? = nil,
                         prerelease: Bool = false, draft: Bool = false) throws -> Data {
        let asset: [String: Any] = ["size": 4, "name": "Russian-Armor.dmg",
            "browser_download_url": url ?? base + tag + "/Russian-Armor.dmg", "digest": digest ?? "sha256:" + fixtureHash]
        return try JSONSerialization.data(withJSONObject: ["tag_name": tag, "prerelease": prerelease, "draft": draft, "assets": [asset]])
    }

    func testStableVersionsAreComparedNumericallyAndOnlyOfferUpgrades() throws {
        let result = try XCTUnwrap(GitHubUpdate.available(in: release(), after: current))
        XCTAssertEqual(result.version.description, "0.2.10")
        XCTAssertEqual(result.url.absoluteString, base + "v0.2.10/Russian-Armor.dmg")
        XCTAssertNil(try GitHubUpdate.available(in: release(tag: "v0.2.2"), after: current))
        XCTAssertNil(try GitHubUpdate.available(in: release(tag: "v0.1.99"), after: current))
        for input in ["1.2", "1.-2.3", "1.02.3", "1.2.3-beta", "v1.2.3", "1.2.3.4"] {
            XCTAssertNil(ReleaseVersion(input))
        }
    }

    func testUntrustedMetadataAndRedirectsCannotSelectAnInstaller() throws {
        for invalid in [try release(url: "https://example.com/Russian-Armor.dmg"),
                        try release(url: base + "v0.2.3/Russian-Armor.dmg"), try release(digest: "sha256:bad"),
                        try release(prerelease: true), try release(draft: true)] {
            XCTAssertThrowsError(try GitHubUpdate.available(in: invalid, after: current))
        }
        XCTAssertTrue(GitHubUpdate.trusted(URL(string: "https://release-assets.githubusercontent.com/asset")!))
        for bad in ["http://github.com", "https://github.com.evil.example", "https://github.com:443/a", "https://user@github.com/a"] {
            XCTAssertFalse(GitHubUpdate.trusted(URL(string: bad)!))
        }
    }

    func testDigestAndSizeMustBothMatchDownloadedBytes() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        let body = Data("test".utf8)
        try body.write(to: file)
        let hash = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        let update = try XCTUnwrap(GitHubUpdate.available(in: release(digest: "sha256:" + hash), after: current))
        XCTAssertNoThrow(try UpdateInstaller.verify(image: file, update: update))
        try Data("tEst".utf8).write(to: file)
        XCTAssertThrowsError(try UpdateInstaller.verify(image: file, update: update))
        try Data("tes".utf8).write(to: file)
        XCTAssertThrowsError(try UpdateInstaller.verify(image: file, update: update))
    }

    func testInstallAndCancelFromReleaseImagesInDisposableApplications() async throws {
        // The fixture app and DMG can be from a published release or a local
        // build. Only a disposable copy of the old bundle is ever replaced.
        let env = ProcessInfo.processInfo.environment
        guard let previous = env["ARMOR_UPDATE_TEST_OLD_APP"], let image = env["ARMOR_UPDATE_TEST_DMG"],
              let hash = env["ARMOR_UPDATE_TEST_SHA256"], let tag = env["ARMOR_UPDATE_TEST_VERSION"],
              let target = ReleaseVersion(tag) else { throw XCTSkip("Requires two packaged versions") }
        let fm = FileManager.default
        let directory = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? fm.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("Russian Armor.app")
        try fm.copyItem(at: URL(fileURLWithPath: previous), to: destination)
        let info = destination.appendingPathComponent("Contents/Info.plist")
        func installedVersion() throws -> ReleaseVersion {
            let plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: info), format: nil) as? [String: Any]
            return try XCTUnwrap((plist?["CFBundleShortVersionString"] as? String).flatMap(ReleaseVersion.init))
        }
        let old = try installedVersion()
        let imageURL = URL(fileURLWithPath: image)
        let size = try XCTUnwrap(imageURL.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        let update = GitHubUpdate(version: target, url: imageURL, size: Int64(size), sha256: hash)
        func stage() throws -> PreparedUpdate {
            try UpdateInstaller.prepare(image: imageURL, update: update, destination: destination, current: old)
        }
        let cancelled = try stage()
        cancelled.discard()
        XCTAssertEqual(try installedVersion(), old)
        let staged = try stage()
        defer { staged.discard() }
        let stale = try stage()
        defer { stale.discard() }
        try staged.install()
        XCTAssertEqual(try installedVersion(), target)
        XCTAssertThrowsError(try stale.install())
        XCTAssertEqual(try installedVersion(), target)
    }

    @MainActor
    func testCheckAndInstallFromPublishedGitHubReleaseOfferRestartOnlyAfterVerification() async throws {
        guard let previous = ProcessInfo.processInfo.environment["ARMOR_UPDATE_LIVE_TEST_APP"] else { throw XCTSkip("Opt-in public release download") }
        let destination = URL(fileURLWithPath: previous)
        let bundle = try XCTUnwrap(Bundle(url: destination))
        let session = URLSession(configuration: .ephemeral, delegate: GitHubRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let ready = expectation(description: "Verified bundle ready to install")
        let updater = ApplicationUpdater(bundle: bundle, session: session) { ready.fulfill() }
        XCTAssertNil(updater.available)
        await updater.check()
        XCTAssertNotNil(updater.available, updater.message ?? "")
        XCTAssertFalse(updater.busy)
        updater.install()
        XCTAssertTrue(updater.busy)
        updater.install() // Ignore a second click during the download.
        await fulfillment(of: [ready], timeout: 120)
        XCTAssertNotNil(updater.prepared, updater.message ?? "")
        updater.discard()
        XCTAssertNil(updater.prepared)
        XCTAssertFalse(updater.busy)
        XCTAssertNotNil(updater.available)
    }
}
