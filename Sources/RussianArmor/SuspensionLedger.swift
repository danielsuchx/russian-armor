import ArmorCore
import Darwin
import Foundation

/// Only process identities owned by Russian Armor, never commands, IPs or tokens.
/// Shared by the main app and its watchdog after the parent process has exited.
struct SuspensionLedger {
    enum LedgerError: Error { case unsafeLocation, invalidData }

    let directory: URL
    private var file: URL { directory.appendingPathComponent("suspended-processes.json") }

    init(directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Russian Armor", isDirectory: true)
    }

    func load() throws -> Set<ProtectedProcessIdentity> {
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        try validateDirectory()
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              attributes[.ownerAccountID] as? UInt32 == getuid(),
              (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 1_048_576 else {
            throw LedgerError.unsafeLocation
        }
        let values = try JSONDecoder().decode([ProtectedProcessIdentity].self, from: Data(contentsOf: file))
        guard values.count <= 16_384,
              values.allSatisfy({ $0.pid > 1 && $0.startMicroseconds < 1_000_000 }) else {
            throw LedgerError.invalidData
        }
        return Set(values)
    }

    func prepareDirectory() throws {
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                   attributes: [.posixPermissions: 0o700])
        }
        try validateDirectory()
    }

    func save(_ values: Set<ProtectedProcessIdentity>) throws {
        try prepareDirectory()
        // Reject a symlink rather than overwriting a destination outside the ledger.
        if let attrs = try? FileManager.default.attributesOfItem(atPath: file.path),
           attrs[.type] as? FileAttributeType != .typeRegular { throw LedgerError.unsafeLocation }
        let data = try JSONEncoder().encode(values.sorted { $0.pid < $1.pid })
        try data.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }

    private func validateDirectory() throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory,
              attributes[.ownerAccountID] as? UInt32 == getuid() else { throw LedgerError.unsafeLocation }
        // Other local users must not be able to inject process identities.
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
}

/// Two app instances must never run contradictory pause/resume policies.
final class ProtectionInstanceLock {
    enum LockError: Error { case alreadyRunning, unavailable }
    private let descriptor: Int32

    init(directory: URL? = nil) throws {
        let ledger = SuspensionLedger(directory: directory)
        try ledger.prepareDirectory()
        let path = ledger.directory.appendingPathComponent("instance.lock").path
        let fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { throw LockError.unavailable }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            let busy = errno == EWOULDBLOCK
            Darwin.close(fd)
            throw busy ? LockError.alreadyRunning : LockError.unavailable
        }
        descriptor = fd
    }

    deinit {
        flock(descriptor, LOCK_UN)
        Darwin.close(descriptor)
    }
}
