import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

final class ClaudeBrowserTests: XCTestCase {
    func testProtectedProfileCannotMatchPersonalOrPrefixSimilarBrowserProfiles() {
        let profile = URL(fileURLWithPath: "/tmp/armor-tests/Claude Browser")
        XCTAssertTrue(ClaudeBrowserLauncher.isProtectedProfile(arguments: ClaudeBrowserLauncher.arguments(profile: profile), profile: profile))
        for other in ["/tmp/personal", profile.path + "-personal", "/tmp/Claude Browser"] {
            XCTAssertFalse(ClaudeBrowserLauncher.isProtectedProfile(arguments: ClaudeBrowserLauncher.arguments(profile: URL(fileURLWithPath: other)), profile: profile))
        }
        XCTAssertFalse(ClaudeBrowserLauncher.isProtectedProfile(arguments: ["--user-data-dir=\(profile.path)"], profile: profile))
    }

    func testClaudeProfileUsesSecureDNSWithoutPlaintextFallback() {
        XCTAssertTrue(ClaudeBrowserLauncher.protectionArguments.contains("--dns-over-https-mode=secure"))
        XCTAssertTrue(ClaudeBrowserLauncher.protectionArguments.contains("--dns-over-https-templates=https://cloudflare-dns.com/dns-query"))
        XCTAssertTrue(ClaudeBrowserLauncher.protectionArguments.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"))
        XCTAssertTrue(ClaudeBrowserLauncher.protectionArguments.contains("--disable-quic"))
        let args = ClaudeBrowserLauncher.arguments(profile: URL(fileURLWithPath: "/tmp/claude"))
        XCTAssertTrue(ClaudeBrowserLauncher.protectionArguments.allSatisfy(args.contains))
    }
    func testOnlyDedicatedBrowserFamilyEntersProcessProtectionCatalog() {
        func record(_ pid: Int32, parent: Int32 = 1, protected: Bool = false) -> ProtectedProcessRecord {
            .init(identity: .init(pid: pid, startSeconds: 10, startMicroseconds: 0), parentPID: parent,
                  executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", processName: "Google Chrome",
                  isClaudeDesktopRoot: protected, isClaudeCodeInterpreter: false)
        }
        let selected = ProtectedProcessCatalog.protectedRecords(from: [record(10, protected: true), record(11, parent: 10), record(20), record(21, parent: 20)])
        XCTAssertEqual(Set(selected.map(\.identity.pid)), [10, 11])
        XCTAssertTrue(selected.allSatisfy { $0.application == .desktop })
    }
}
