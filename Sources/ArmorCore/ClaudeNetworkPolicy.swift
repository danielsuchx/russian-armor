import Foundation

/// A short permission lease; WebRTC/UDP is denied even while TCP is permitted.
/// This policy never chooses a route or grants permission to unrelated apps.
public struct ClaudeNetworkPolicy: Codable, Sendable {
    public struct Process: Codable, Sendable {
        public let identity: ProtectedProcessIdentity
        public let application: ProtectedApplication
        public init(identity: ProtectedProcessIdentity, application: ProtectedApplication) {
            self.identity = identity; self.application = application
        }
    }
    public let desktopAllowed: Bool
    public let codeAllowed: Bool
    public let processes: [Process]
    public let issuedAtUptime: TimeInterval
    public init(desktopAllowed: Bool, codeAllowed: Bool, processes: [Process], issuedAtUptime: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        self.desktopAllowed = desktopAllowed; self.codeAllowed = codeAllowed; self.processes = processes
        self.issuedAtUptime = issuedAtUptime
    }
    public func permits(_ application: ProtectedApplication, udp: Bool, receivedAt: TimeInterval, now: TimeInterval) -> Bool {
        guard !udp, now >= receivedAt, now >= issuedAtUptime, now - min(receivedAt, issuedAtUptime) < 4 else { return false }
        return application == .desktop ? desktopAllowed : codeAllowed
    }
}
