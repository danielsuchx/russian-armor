import ArmorCore
import Darwin
import Foundation

/// Fixed paths only; no privileged shell, user-supplied executable or PF text.
enum FirewallPaths {
    static let directory = "/Library/Application Support/Russian Armor Firewall"
    static let binary = "/Library/PrivilegedHelperTools/app.russian-armor.firewall"
    static let plist = "/Library/LaunchDaemons/app.russian-armor.firewall.plist"
    static let configuration = directory + "/configuration.json"
    static let armed = directory + "/armed"
    static let status = directory + "/status.json"
    static let backup = directory + "/original.pf.conf"
    static let main = "/private/etc/pf.conf"
    static let anchor = "/private/etc/pf.anchors/app.russian-armor"
    static let label = "app.russian-armor.firewall"
}

/// Never follows a writable-directory symlink when reading or replacing root state.
enum RootFiles {
    static func requireRoot() throws { guard geteuid() == 0 else { throw FirewallError.requiresRoot } }

    static func checkDirectory(_ path: String, create: Bool = false) throws {
        try requireRoot()
        var current = ""
        for part in path.split(separator: "/") {
            current += "/" + part
            if create, mkdir(current, 0o755) != 0, errno != EEXIST { throw FirewallError.unsafeFile }
            var info = stat()
            guard lstat(current, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == 0, info.st_mode & 0o022 == 0 else { throw FirewallError.unsafeFile }
        }
    }

    static func read(_ path: String, rootOwned: Bool = true, limit: Int = 65_536) throws -> Data {
        if rootOwned { try checkDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path) }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw FirewallError.unsafeFile }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
              info.st_size >= 0, info.st_size <= limit,
              !rootOwned || (info.st_uid == 0 && info.st_mode & 0o022 == 0) else { throw FirewallError.unsafeFile }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
        let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        guard count == info.st_size else { throw FirewallError.unsafeFile }
        return Data(bytes.prefix(count))
    }

    static func exists(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0
    }

    static func write(_ data: Data, to path: String, mode: mode_t = 0o600) throws {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        try checkDirectory(parent)
        if exists(path) { _ = try read(path, limit: 64 * 1024 * 1024) }
        let temp = parent + "/.armor-" + UUID().uuidString
        let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw FirewallError.unsafeFile }
        defer { close(fd); unlink(temp) }
        guard fchmod(fd, mode) == 0,
              data.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, $0.count) }) == data.count,
              fsync(fd) == 0, rename(temp, path) == 0 else { throw FirewallError.unsafeFile }
        let directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw FirewallError.unsafeFile }
        defer { close(directory) }
        guard fsync(directory) == 0 else { throw FirewallError.unsafeFile }
    }
    static func remove(_ path: String) throws {
        guard exists(path) else { return }
        _ = try read(path)
        guard unlink(path) == 0 else { throw FirewallError.unsafeFile }
    }
    static func locked<T>(_ body: () throws -> T) throws -> T {
        try checkDirectory(FirewallPaths.directory)
        let path = FirewallPaths.directory + "/control.lock"
        let fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw FirewallError.unsafeFile }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o077 == 0, info.st_nlink == 1, flock(fd, LOCK_EX) == 0 else { throw FirewallError.unsafeFile }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }
}

typealias SystemCommand = (_ executable: String, _ arguments: [String]) throws -> String

func systemCommand(_ executable: String, _ arguments: [String]) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "HOME": "/var/empty"]
    process.currentDirectoryURL = URL(fileURLWithPath: "/")
    let pipe = Pipe()
    process.standardOutput = pipe
    // pfctl writes its enable-reference token to stderr on some macOS releases.
    process.standardError = arguments == ["-E"] ? pipe : FileHandle.standardError
    try process.run()
    let timer = DispatchSource.makeTimerSource()
    timer.schedule(deadline: .now() + 5)
    timer.setEventHandler { if process.isRunning { kill(process.processIdentifier, SIGKILL) } }
    timer.resume()
    defer { timer.cancel() }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard data.count < 1_048_576, process.terminationStatus == 0 else {
        // Avoid persisting addresses or untrusted tool output in status files.
        throw FirewallError.commandFailed(URL(fileURLWithPath: executable).lastPathComponent + " " + arguments.prefix(2).joined(separator: " "))
    }
    return String(decoding: data, as: UTF8.self)
}

struct PFDriver {
    var command: SystemCommand = systemCommand
    static let pfctl = "/sbin/pfctl"

    func validate(_ path: String) throws { _ = try command(Self.pfctl, ["-n", "-f", path]) }
    func loadMain() throws { _ = try command(Self.pfctl, ["-f", FirewallPaths.main]) }
    func applyAnchor() throws { _ = try command(Self.pfctl, ["-a", FirewallRules.anchor, "-f", FirewallPaths.anchor]) }
    func flushStates() throws { _ = try command(Self.pfctl, ["-F", "states"]) }
    func isEnabled() throws -> Bool {
        try command(Self.pfctl, ["-s", "info"]).components(separatedBy: .newlines).contains { $0.hasPrefix("Status: Enabled") }
    }
    func acquireReference() throws -> String {
        let output = try command(Self.pfctl, ["-E"])
        let tokens = output.components(separatedBy: .newlines).compactMap { line -> String? in
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, parts[0] == "Token", UInt64(parts[1]) != nil else { return nil }
            return parts[1]
        }
        guard tokens.count == 1 else { throw FirewallError.commandFailed("pfctl enable reference") }
        return tokens[0]
    }
    func releaseReference(_ token: String) throws {
        guard UInt64(token) != nil else { throw FirewallError.unsafeFile }
        _ = try command(Self.pfctl, ["-X", token])
    }
    func activateMain(ensureEnabled: () throws -> Void) throws {
        try validate(FirewallPaths.main)
        try loadMain()
        try ensureEnabled()
        try flushStates()
        try verifyMain(armed: true)
    }
    func verifyNoTranslations() throws {
        // A NAT/rdr rule with 'pass' can bypass filtering. This MVP refuses
        // active translations (including Internet Sharing) instead of claiming
        // that a filtering anchor controls packets it never receives.
        let lines = FirewallRules.statements(try command(Self.pfctl, ["-a", "*", "-s", "nat"]))
        guard lines.allSatisfy({ line in
            line == "}" || line.hasPrefix("nat-anchor ") || line.hasPrefix("rdr-anchor ") || line.hasPrefix("binat-anchor ")
        }) else { throw FirewallError.incompatiblePF }
    }
    func mainFilterRules() throws -> [String] {
        // Some macOS pfctl versions include normalization/dummynet anchor
        // declarations in -sr. Only these exact stock declarations are ignored.
        let stockNonFilter: Set<String> = ["scrub-anchor \"com.apple/*\" all fragment reassemble",
                                          "dummynet-anchor \"com.apple/*\" all"]
        return FirewallRules.statements(try command(Self.pfctl, ["-s", "rules"]))
            .filter { !stockNonFilter.contains($0) }
    }
    func verifyMain(armed: Bool) throws {
        let lines = try mainFilterRules()
        let expected = armed ? ["anchor \"app.russian-armor\" quick all", "anchor \"com.apple/*\" all"] : ["anchor \"com.apple/*\" all"]
        guard lines == expected || (!armed && lines.isEmpty) else { throw FirewallError.incompatiblePF }
    }
}
