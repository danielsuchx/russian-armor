import ArmorCore
import Foundation

/// Reads existing snapshots only. Building a report must not send requests,
/// enumerate processes, change settings or grant permission to resume Claude.
@MainActor
enum DiagnosticReportBuilder {
    static func build(at date: Date, appVersion: String?, vpnLocation: VPNLocation,
                      protection: ProtectionState, external: ExternalCheckState,
                      confirmedEgress: EgressObservation?, routes: ClaudeRouteState,
                      diagnostics: ConnectionDiagnosticsMonitor.State,
                      servicesEnabled: Bool, watchdogHealthy: Bool?, sleeping: Bool) -> DiagnosticReport {
        var checks = [egress(external, confirmed: confirmedEgress), route(routes, at: date, vpnLocation: vpnLocation)]
        checks.append(dns(diagnostics, at: date))
        for service in ServiceProbe.allCases {
            checks.append(endpoint(service, state: diagnostics, at: date,
                                   enabled: servicesEnabled, expectedIP: confirmedEgress?.ip))
        }
        if let watchdogHealthy {
            checks.append(.init(.watchdog, watchdogHealthy ? .observed : .attention,
                                watchdogHealthy ? .watchdogResponding : .watchdogUnavailable))
        } else {
            checks.append(.init(.watchdog, .notChecked, .awaitingCheck))
        }
        if sleeping {
            checks = checks.map { .init($0.id, .sleeping, .sleeping) }
        }
        return DiagnosticReport(createdAt: date, appVersion: appVersion, vpnLocation: vpnLocation,
                                controllerState: controller(protection, hasEgress: confirmedEgress != nil, sleeping: sleeping),
                                checks: checks)
    }

    private static func controller(_ state: ProtectionState, hasEgress: Bool,
                                   sleeping: Bool) -> DiagnosticReport.ControllerState {
        switch state {
        case .notConfigured: return .unavailable
        case .setupRequired, .approvalRequired, .restartRequired: return .needsSetup
        case .configuring: return .checking
        case .countryConfirmed: return hasEgress && !sleeping ? .countryControlActive : .paused
        case .channelEnabled: return .systemChannelEnabled
        case .paused: return .paused
        case .failed: return .failed
        }
    }

    private static func egress(_ state: ExternalCheckState, confirmed: EgressObservation?) -> DiagnosticReport.Check {
        if confirmed != nil { return .init(.egress, .observed, .armorEgressOnly) }
        switch state {
        case .notChecked: return .init(.egress, .notChecked, .awaitingCheck)
        case .checking: return .init(.egress, .checking, .checking)
        case .failed: return .init(.egress, .unavailable, .requestFailed)
        case .observed, .needsRecheck: return .init(.egress, .stale, .noFreshEgress)
        }
    }

    private static func route(_ state: ClaudeRouteState, at date: Date, vpnLocation: VPNLocation) -> DiagnosticReport.Check {
        switch state {
        case .off: return .init(.claudeRoutes, .disabled, .disabled)
        case .checking: return .init(.claudeRoutes, .checking, .checking)
        case .sleeping: return .init(.claudeRoutes, .sleeping, .sleeping)
        case .failed: return .init(.claudeRoutes, .unavailable, .routeUnknown)
        case .observed(let snapshot):
            guard fresh(snapshot.capturedAt, at: date, lifetime: ClaudeRouteMonitor.maximumAge) else {
                return .init(.claudeRoutes, .stale, .expired)
            }
            if snapshot.isPartial { return .init(.claudeRoutes, .unavailable, .partialSnapshot) }
            if snapshot.routes.contains(where: { $0.path == .unknown }) {
                return .init(.claudeRoutes, .unavailable, .routeUnknown)
            }
            if vpnLocation == .thisMac, snapshot.routes.contains(where: {
                if case .outsideTunnel = $0.path { return true }; return false
            }) { return .init(.claudeRoutes, .attention, .routeOutsideTunnel) }
            if snapshot.routes.isEmpty { return .init(.claudeRoutes, .observed, .noExternalSockets) }
            if vpnLocation != .thisMac || snapshot.routes.contains(where: { $0.path == .localPeer }) {
                return .init(.claudeRoutes, .observed, .downstreamUnknown)
            }
            return .init(.claudeRoutes, .observed, .routeSnapshotOnly)
        }
    }

    private static func pending(_ id: DiagnosticReport.CheckID, state: ConnectionDiagnosticsMonitor.State,
                                at date: Date) -> DiagnosticReport.Check? {
        switch state {
        case .notChecked: return .init(id, .notChecked, .awaitingCheck)
        case .checking: return .init(id, .checking, .checking)
        case .sleeping: return .init(id, .sleeping, .sleeping)
        case .stale: return .init(id, .stale, .expired)
        case .observed(let snapshot):
            return fresh(snapshot.checkedAt, at: date, lifetime: ConnectionDiagnosticsMonitor.maximumAge)
                ? nil : .init(id, .stale, .expired)
        }
    }

    private static func dns(_ state: ConnectionDiagnosticsMonitor.State, at date: Date) -> DiagnosticReport.Check {
        if let pending = pending(.dnsConfiguration, state: state, at: date) { return pending }
        guard case .observed(let snapshot) = state, !snapshot.dnsServers.isEmpty else {
            return .init(.dnsConfiguration, .unavailable, .dnsUnavailable)
        }
        return .init(.dnsConfiguration, .observed, .configuredDNSOnly)
    }

    private static func endpoint(_ service: ServiceProbe, state: ConnectionDiagnosticsMonitor.State,
                                 at date: Date, enabled: Bool, expectedIP: String?) -> DiagnosticReport.Check {
        let id: DiagnosticReport.CheckID = service == .desktop ? .desktopEndpoint : .codeEndpoint
        guard enabled else { return .init(id, .disabled, .disabled) }
        if let pending = pending(id, state: state, at: date) { return pending }
        guard case .observed(let snapshot) = state, let result = snapshot.services[service] else {
            return .init(id, .notChecked, .awaitingCheck)
        }
        switch result {
        case .unavailable: return .init(id, .unavailable, .endpointUnavailable)
        case .observed(let address):
            guard let expectedIP else { return .init(id, .observed, .endpointWithoutComparison) }
            let matches = IPRange(address)?.contains(expectedIP) == true
            return .init(id, matches ? .observed : .attention, matches ? .endpointMatches : .endpointDiffers)
        }
    }

    private static func fresh(_ checkedAt: Date, at date: Date, lifetime: TimeInterval) -> Bool {
        let age = date.timeIntervalSince(checkedAt)
        return age >= 0 && age < lifetime
    }
}
