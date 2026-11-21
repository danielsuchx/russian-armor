import CryptoKit
import Darwin
import Foundation
import Security

/// All slow work is performed before asking the user to close Claude. The
/// only operation on the running bundle is a same-volume atomic exchange.
struct PreparedUpdate {
    let destination: URL
    private let directory: URL
    private let original: BundleIdentity
    private let current: ReleaseVersion
    private var staged: URL { directory.appendingPathComponent("Russian Armor.app") }

    fileprivate init(destination: URL, directory: URL, original: BundleIdentity, current: ReleaseVersion) {
        self.destination = destination
        self.directory = directory
        self.original = original
        self.current = current
    }

    func install() throws {
        guard try BundleIdentity(destination) == original, try UpdateInstaller.version(of: destination) == current else { throw AppUpdateError.replaced }
        guard renamex_np(staged.path, destination.path, UInt32(RENAME_SWAP)) == 0 else { throw AppUpdateError.destination }
    }

    func discard() {
        try? FileManager.default.removeItem(at: directory)
    }
}

fileprivate struct BundleIdentity: Equatable {
    let device: dev_t
    let inode: ino_t

    init(_ url: URL) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else { throw AppUpdateError.destination }
        device = info.st_dev
        inode = info.st_ino
    }
}

enum UpdateInstaller {
    private static let bundleID = "app.russian-armor.desktop"

    static func download(_ update: GitHubUpdate, to destination: URL, current: ReleaseVersion, session: URLSession) async throws -> PreparedUpdate {
        let (image, response) = try await session.download(from: update.url)
        defer { try? FileManager.default.removeItem(at: image) }
        try GitHubUpdate.validate(response)
        return try await Task.detached(priority: .utility) {
            try prepare(image: image, update: update, destination: destination, current: current)
        }.value
    }

    static func verify(image: URL, update: GitHubUpdate) throws {
        let file = try FileHandle(forReadingFrom: image)
        defer { try? file.close() }
        guard try file.seekToEnd() == UInt64(update.size) else { throw AppUpdateError.invalidDownload }
        try file.seek(toOffset: 0)
        var hash = SHA256()
        while let chunk = try file.read(upToCount: 1_048_576), !chunk.isEmpty { hash.update(data: chunk) }
        let actual = hash.finalize().map { String(format: "%02x", $0) }.joined()
        guard actual == update.sha256 else { throw AppUpdateError.invalidDownload }
    }

    static func prepare(image: URL, update: GitHubUpdate, destination: URL, current: ReleaseVersion) throws -> PreparedUpdate {
        let fm = FileManager.default
        guard update.version > current, destination.pathExtension == "app",
              !destination.pathComponents.contains("AppTranslocation"),
              fm.isWritableFile(atPath: destination.deletingLastPathComponent().path) else { throw AppUpdateError.destination }
        let identity = try BundleIdentity(destination)
        guard try version(of: destination) == current else { throw AppUpdateError.replaced }
        try verify(image: image, update: update)

        // The replacement directory is on the installed app's volume, even
        // when the download is in a temporary directory on a different disk.
        let staging = try fm.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: destination, create: true)
        do {
            let candidate = staging.appendingPathComponent("Russian Armor.app")
            try copyFromImage(image, to: candidate)
            guard try version(of: candidate) == update.version else { throw AppUpdateError.invalidBundle }
            try validateSignature(candidate, installed: destination)
            try requireCompatibleMac(candidate)
            return PreparedUpdate(destination: destination, directory: staging, original: identity, current: current)
        } catch {
            try? fm.removeItem(at: staging)
            throw error
        }
    }

    fileprivate static func version(of app: URL) throws -> ReleaseVersion {
        // Bundle(url:) can cache an Info.plist across a replacement at the same path.
        let data = try Data(contentsOf: app.appendingPathComponent("Contents/Info.plist"))
        let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        guard info?["CFBundleIdentifier"] as? String == bundleID, info?["CFBundleExecutable"] as? String == "RussianArmor",
              let raw = info?["CFBundleShortVersionString"] as? String, let version = ReleaseVersion(raw) else { throw AppUpdateError.invalidBundle }
        return version
    }

    private static func requireCompatibleMac(_ app: URL) throws {
        #if arch(arm64)
        let architecture = NSBundleExecutableArchitectureARM64
        #else
        let architecture = NSBundleExecutableArchitectureX86_64
        #endif
        guard let bundle = Bundle(url: app),
              bundle.executableArchitectures?.contains(NSNumber(value: architecture)) == true else { throw AppUpdateError.incompatible }
        if let minimum = bundle.object(forInfoDictionaryKey: "LSMinimumSystemVersion") as? String {
            let fields = minimum.split(separator: ".", omittingEmptySubsequences: false)
            let parts = fields.compactMap { Int($0) }
            guard (1...3).contains(fields.count), parts.count == fields.count, parts.allSatisfy({ $0 >= 0 }) else { throw AppUpdateError.invalidBundle }
            let version = OperatingSystemVersion(majorVersion: parts[0], minorVersion: parts.count > 1 ? parts[1] : 0, patchVersion: parts.count > 2 ? parts[2] : 0)
            guard ProcessInfo.processInfo.isOperatingSystemAtLeast(version) else { throw AppUpdateError.incompatible }
        }
    }

    private static func copyFromImage(_ image: URL, to candidate: URL) throws {
        let fm = FileManager.default
        let mount = fm.temporaryDirectory.appendingPathComponent("RussianArmorMount-" + UUID().uuidString)
        try fm.createDirectory(at: mount, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { _ = rmdir(mount.path) } // Never recursively remove a mounted volume.
        try run("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount.path, image.path], error: .diskImage)
        defer {
            if (try? run("/usr/bin/hdiutil", ["detach", mount.path], error: .diskImage)) == nil {
                try? run("/usr/bin/hdiutil", ["detach", mount.path, "-force"], error: .diskImage)
            }
        }
        let source = mount.appendingPathComponent("Russian Armor.app")
        _ = try BundleIdentity(source)
        try run("/usr/bin/ditto", [source.path, candidate.path], error: .diskImage)
    }

    private static func validateSignature(_ candidate: URL, installed: URL) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(installed as CFURL, [], &code) == errSecSuccess, let code else { throw AppUpdateError.invalidBundle }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let values = info as? [String: Any] else { throw AppUpdateError.invalidBundle }
        var requirement = "identifier \"\(bundleID)\""
        if let team = values[kSecCodeInfoTeamIdentifier as String] as? String {
            guard team.utf8.count == 10, team.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }) else { throw AppUpdateError.invalidBundle }
            requirement += " and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        }
        let arguments = ["--verify", "--deep", "--strict", "--all-architectures", "-R=" + requirement, candidate.path]
        try run("/usr/bin/codesign", arguments, error: .invalidBundle)
    }

    private static func run(_ executable: String, _ arguments: [String], error: AppUpdateError) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationReason == .exit && process.terminationStatus == 0 else { throw error }
    }
}
