import AppKit
import Foundation

/// The profile belongs only to Claude. Personal browser profiles and their
/// WebRTC policy, extensions, cookies and routes are never edited.
enum ClaudeBrowserLauncher {
    static let browserIDs = ["com.google.Chrome", "com.brave.Browser", "org.chromium.Chromium", "com.microsoft.edgemac"]
    static var profile: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Russian Armor/Claude Browser", isDirectory: true)
    }
    /// Chromium policies are passed at process creation, so an ordinary browser
    /// profile and its DNS/WebRTC behavior stay untouched.
    static let protectionArguments = [
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic",
        "--dns-over-https-mode=secure",
        "--dns-over-https-templates=https://cloudflare-dns.com/dns-query"
    ]
    static func arguments(profile: URL) -> [String] {
        ["--user-data-dir=\(profile.path)"] + protectionArguments + ["--no-first-run",
         "--no-default-browser-check", "--new-window", "https://claude.ai"]
    }
    static func isProtectedProfile(arguments: [String], profile: URL = profile) -> Bool {
        arguments.contains("--user-data-dir=\(profile.path)")
            && protectionArguments.allSatisfy(arguments.contains)
    }
    @MainActor static func launch() async throws {
        guard let url = browserIDs.lazy.compactMap({ NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }).first,
              let executable = Bundle(url: url)?.executableURL else { throw LaunchError.browserMissing }
        try FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // Start a separate browser process; the ordinary profile keeps running.
        let child = Process()
        child.executableURL = executable
        child.arguments = arguments(profile: profile)
        child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
        try child.run()
        try await Task.sleep(nanoseconds: 300_000_000)
        guard child.isRunning || child.terminationStatus == 0 else { throw LaunchError.launchFailed }
    }
    enum LaunchError: Error, LocalizedError {
        case browserMissing, launchFailed
        var errorDescription: String? {
            switch self {
            case .browserMissing: return "Для отдельного профиля Claude нужен Chrome, Brave, Chromium или Edge."
            case .launchFailed: return "Не удалось открыть профиль Claude с ограничением WebRTC."
            }
        }
    }
}
