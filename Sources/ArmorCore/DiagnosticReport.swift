import Foundation

/// Shareable diagnostics use an allowlist, not a redacted copy of application
/// state. Never add raw errors, preferences, events, addresses or profile names.
public struct DiagnosticReport: Codable, Equatable, Sendable {
    public enum CheckID: String, Codable, Sendable {
        case egress, claudeRoutes, dnsConfiguration, desktopEndpoint, codeEndpoint, watchdog
    }

    public enum Status: String, Codable, Sendable {
        case observed, attention, unavailable, notChecked, checking, stale, disabled, sleeping
    }

    public enum Finding: String, Codable, Sendable {
        case armorEgressOnly, noFreshEgress, requestFailed
        case routeSnapshotOnly, noExternalSockets, downstreamUnknown, routeOutsideTunnel, routeUnknown, partialSnapshot
        case configuredDNSOnly, dnsUnavailable
        case endpointMatches, endpointDiffers, endpointWithoutComparison, endpointUnavailable
        case watchdogResponding, watchdogUnavailable, awaitingCheck, checking, expired, disabled, sleeping
    }

    public struct Check: Codable, Equatable, Sendable, Identifiable {
        public let id: CheckID
        public let status: Status
        public let finding: Finding

        public init(_ id: CheckID, _ status: Status, _ finding: Finding) {
            self.id = id
            self.status = status
            self.finding = finding
        }
    }

    public enum ControllerState: String, Codable, Sendable {
        case unavailable, needsSetup, checking, countryControlActive, paused, failed, systemChannelEnabled
    }

    public let schemaVersion: Int
    public let createdAt: Date
    public let appVersion: String?
    public let vpnLocation: VPNLocation
    public let controllerState: ControllerState
    public let checks: [Check]

    public init(createdAt: Date, appVersion: String?, vpnLocation: VPNLocation,
                controllerState: ControllerState, checks: [Check]) {
        schemaVersion = 1
        self.createdAt = createdAt
        // Bundle metadata is the only string accepted by the report. Keep it
        // numeric so an untrusted build cannot put paths or secrets here.
        self.appVersion = appVersion.flatMap { version in
            let parts = version.split(separator: ".", omittingEmptySubsequences: false)
            guard (2...3).contains(parts.count), parts.allSatisfy({
                (1...4).contains($0.utf8.count) && $0.utf8.allSatisfy { (48...57).contains($0) }
            }) else { return nil }
            return version
        }
        self.vpnLocation = vpnLocation
        self.controllerState = controllerState
        self.checks = checks
    }

    /// The preview and saved file must use these exact same bytes.
    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(self)
    }
}
