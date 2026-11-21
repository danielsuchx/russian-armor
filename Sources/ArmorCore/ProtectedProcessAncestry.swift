import Foundation

/// Resolves a new socket owner synchronously, before the GUI's next process scan.
/// The caller supplies live, same-user process records and authenticated roots.
public enum ProtectedProcessAncestry {
    public struct Node: Sendable {
        public let identity: ProtectedProcessIdentity
        public let parentPID: Int32
        public let application: ProtectedApplication?

        public init(identity: ProtectedProcessIdentity, parentPID: Int32, application: ProtectedApplication?) {
            self.identity = identity
            self.parentPID = parentPID
            self.application = application
        }
    }

    public static func application(
        for source: ProtectedProcessIdentity,
        read: (Int32) -> Node?
    ) -> ProtectedApplication? {
        var pid = source.pid
        var child = source
        var visited = Set<Int32>()
        for _ in 0..<128 {
            guard pid > 1, visited.insert(pid).inserted,
                  let node = read(pid), node.identity.pid == pid else { return nil }
            if pid == source.pid {
                guard node.identity == source else { return nil }
            } else {
                // A PID reused after its alleged child started cannot be its parent.
                guard node.identity.startSeconds < child.startSeconds
                    || (node.identity.startSeconds == child.startSeconds
                        && node.identity.startMicroseconds <= child.startMicroseconds) else { return nil }
            }
            if let application = node.application { return application }
            child = node.identity
            pid = node.parentPID
        }
        return nil
    }
}
