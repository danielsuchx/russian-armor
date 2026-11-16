import AppKit
import ArmourCore
import Darwin
import Foundation

@MainActor
struct LocalDiagnosticsReader {
    static let claudeBundleIdentifier = "com.anthropic.claudefordesktop"

    static func read() -> LocalDiagnosticsSnapshot {
        LocalDiagnosticsSnapshot(
            tunnels: readTunnels(),
            claudeDesktop: readClaudeDesktop(),
            checkedAt: Date()
        )
    }

    private static func readTunnels() -> TunnelObservation {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return .unavailable }
        defer { if let first { freeifaddrs(first) } }
        var interfaces: [LocalInterface] = []
        var current = first
        while let entry = current {
            let item = entry.pointee
            if let name = item.ifa_name {
                interfaces.append(LocalInterface(
                    name: String(cString: name),
                    isUp: item.ifa_flags & UInt32(IFF_UP) != 0
                ))
            }
            current = item.ifa_next
        }
        // Do not read socket addresses, packet contents or environment variables.
        return TunnelObservation.inspect(interfaces)
    }

    private static func readClaudeDesktop() -> ApplicationPresence {
        let isRunning = NSWorkspace.shared.runningApplications.contains {
            $0.bundleIdentifier == claudeBundleIdentifier && !$0.isTerminated
        }
        if isRunning { return .running }
        return NSWorkspace.shared.urlForApplication(withBundleIdentifier: claudeBundleIdentifier) == nil
            ? .notInstalled : .notRunning
    }
}
