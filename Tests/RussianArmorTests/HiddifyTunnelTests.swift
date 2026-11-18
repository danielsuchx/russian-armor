@testable import ArmorTunnel
import Foundation
import Security
import XCTest

final class HiddifyTunnelTests: XCTestCase {
    func testOnlyOfficialRootServicePathsAndExtensionCanUsePrivilegedReader() {
        let base = "/Library/Application Support/Hiddify"
        let binary = "/Hiddify.app/Contents/MacOS/Hiddify"
        XCTAssertEqual(TunnelProvider.candidate(executable: base + "/AdminBgService" + binary, uid: 0), .hiddifyService)
        XCTAssertEqual(TunnelProvider.candidate(executable: base + "/TunnelService" + binary, uid: 0), .hiddifyService)
        XCTAssertNil(TunnelProvider.candidate(executable: base + "/AdminBgService" + binary, uid: 501))
        XCTAssertNil(TunnelProvider.candidate(executable: "/Applications" + binary, uid: 0))
        XCTAssertNil(TunnelProvider.candidate(executable: "/tmp/Hiddify", uid: 0))
        XCTAssertEqual(TunnelProvider.candidate(executable: "/some/extension/Contents/MacOS/HiddifyPacketTunnel", uid: 501), .hiddifyExtension)
        XCTAssertEqual(TunnelProvider.candidate(executable: "/a/verge-mihomo", uid: 0), .clash)
        XCTAssertNil(TunnelProvider.candidate(executable: "/a/verge-mihomo", uid: 501))
    }

    func testHiddifyAndClashRequirementsRejectAnUnrelatedSignedExecutable() throws {
        var code: SecStaticCode?
        XCTAssertEqual(SecStaticCodeCreateWithPath(URL(fileURLWithPath: "/usr/bin/true") as CFURL, [], &code), errSecSuccess)
        let fixture = try XCTUnwrap(code)
        for provider in [TunnelProvider.hiddifyService, .hiddifyExtension, .clash] {
            var requirement: SecRequirement?
            XCTAssertEqual(SecRequirementCreateWithString(provider.requirement as CFString, [], &requirement), errSecSuccess)
            XCTAssertNotEqual(SecStaticCodeCheckValidity(fixture, [], try XCTUnwrap(requirement)), errSecSuccess)
        }
    }

    func testOfficialHiddifyReleaseIdentitiesOnBothArchitectures() throws {
        let env = ProcessInfo.processInfo.environment
        guard let git = env["ARMOR_HIDDIFY_GITHUB_APP"], let ext = env["ARMOR_HIDDIFY_STORE_EXTENSION"] else {
            throw XCTSkip("Requires the official Hiddify macOS release assets")
        }
        for (path, provider) in [(git, TunnelProvider.hiddifyService), (ext, .hiddifyExtension)] {
            for architecture in ["arm64", "x86_64"] {
                var code: SecStaticCode?
                let attributes = [kSecCodeAttributeArchitecture: architecture] as CFDictionary
                XCTAssertEqual(SecStaticCodeCreateWithPathAndAttributes(URL(fileURLWithPath: path) as CFURL, [], attributes, &code), errSecSuccess)
                var requirement: SecRequirement?
                XCTAssertEqual(SecRequirementCreateWithString(provider.requirement as CFString, [], &requirement), errSecSuccess)
                let status = SecStaticCodeCheckValidity(try XCTUnwrap(code), [], try XCTUnwrap(requirement))
                XCTAssertEqual(status, errSecSuccess, "\(provider) / \(architecture): \(SecCopyErrorMessageString(status, nil) as String? ?? "")")
            }
        }
    }
}
