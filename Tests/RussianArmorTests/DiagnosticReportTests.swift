import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class DiagnosticReportBuilderTests: XCTestCase {
    private let date = Date(timeIntervalSince1970: 1000)

    private func report(external: ExternalCheckState = .notChecked, confirmed: EgressObservation? = nil,
                        routes: ClaudeRouteState = .off,
                        diagnostics: ConnectionDiagnosticsMonitor.State = .notChecked,
                        services: Bool = false, watchdog: Bool? = nil, sleeping: Bool = false,
                        vpn: VPNLocation = .thisMac, protection: ProtectionState = .notConfigured) -> DiagnosticReport {
        DiagnosticReportBuilder.build(at: date, appVersion: "0.2.2", vpnLocation: vpn,
                                      protection: protection, external: external, confirmedEgress: confirmed,
                                      routes: routes, diagnostics: diagnostics, servicesEnabled: services,
                                      watchdogHealthy: watchdog, sleeping: sleeping)
    }

    private func check(_ id: DiagnosticReport.CheckID, in report: DiagnosticReport) throws -> DiagnosticReport.Check {
        try XCTUnwrap(report.checks.first { $0.id == id })
    }

    private func observation(_ ip: String = "203.0.113.17") throws -> EgressObservation {
        try EgressObservation.decode(Data("{\"ip\":\"\(ip)\",\"country\":\"NL\"}".utf8), checkedAt: date)
    }

    private func route(local: String = "10.0.0.7", remote: String = "203.0.113.17",
                       interfaces: [String] = ["utun4"], route: String? = "utun4") -> ClaudeConnectionRoute {
        let process = TrafficProcess(id: .init(pid: 123, startSeconds: 1, startMicroseconds: 0), name: "Claude")
        let connection = TrafficConnection(process: process, socketGeneration: 1, descriptor: 1, transport: .tcp,
                                           local: .init(address: local, port: 50000, version: .v4),
                                           remote: .init(address: remote, port: 443, version: .v4), state: "ESTABLISHED")
        return .init(connection: connection, sourceInterfaces: interfaces, routeInterface: route)
    }

    func testInitialAndDisabledChecksNeverPretendSuccess() throws {
        let initial = report()
        XCTAssertEqual(initial.checks.count, 6)
        XCTAssertEqual(Set(initial.checks.map(\.id)).count, 6)
        XCTAssertEqual(try check(.egress, in: initial).status, .notChecked)
        XCTAssertEqual(try check(.claudeRoutes, in: initial).status, .disabled)
        XCTAssertEqual(try check(.dnsConfiguration, in: initial).status, .notChecked)
        XCTAssertEqual(try check(.desktopEndpoint, in: initial).status, .disabled)
        XCTAssertEqual(try check(.codeEndpoint, in: initial).status, .disabled)
        XCTAssertEqual(try check(.watchdog, in: initial).status, .notChecked)
    }

    func testExpiredEgressDoesNotReuseCachedSuccessOrClaimActiveControl() throws {
        let value = try observation()
        let expired = report(external: .observed(value), protection: .countryConfirmed)
        XCTAssertEqual(try check(.egress, in: expired).status, .stale)
        XCTAssertEqual(expired.controllerState, .paused)
        let refreshing = report(external: .checking, confirmed: value, protection: .countryConfirmed)
        XCTAssertEqual(try check(.egress, in: refreshing).finding, .armorEgressOnly)
        XCTAssertEqual(refreshing.controllerState, .countryControlActive)
        XCTAssertEqual(try check(.egress, in: report(external: .failed("secret"))).status, .unavailable)
    }

    func testRouteFreshnessUsesEnforcementBoundaryIncludingClockRollback() throws {
        for offset in [-1.0, 5.0, 6.0] {
            let snapshot = ClaudeRouteSnapshot(routes: [route()], capturedAt: date.addingTimeInterval(-offset))
            XCTAssertEqual(try check(.claudeRoutes, in: report(routes: .observed(snapshot))).status, .stale)
        }
        let recent = ClaudeRouteSnapshot(routes: [route()], capturedAt: date.addingTimeInterval(-4.99))
        XCTAssertEqual(try check(.claudeRoutes, in: report(routes: .observed(recent))).finding, .routeSnapshotOnly)
    }

    func testEmptyPartialUnknownLocalAndOutsideRoutesHaveDifferentFindings() throws {
        let samples: [([ClaudeConnectionRoute], Bool, DiagnosticReport.Status, DiagnosticReport.Finding)] = [
            ([], false, .observed, .noExternalSockets),
            ([], true, .unavailable, .partialSnapshot),
            ([route(route: nil)], false, .unavailable, .routeUnknown),
            ([route(remote: "127.0.0.1")], false, .observed, .downstreamUnknown),
            ([route(interfaces: ["en0"], route: "en0")], false, .attention, .routeOutsideTunnel)
        ]
        for (routes, partial, status, finding) in samples {
            let snapshot = ClaudeRouteSnapshot(routes: routes, capturedAt: date, isPartial: partial)
            let result = try check(.claudeRoutes, in: report(routes: .observed(snapshot)))
            XCTAssertEqual(result.status, status)
            XCTAssertEqual(result.finding, finding)
        }
        let outside = ClaudeRouteSnapshot(routes: [route(interfaces: ["en0"], route: "en0")], capturedAt: date)
        XCTAssertEqual(try check(.claudeRoutes, in: report(routes: .observed(outside), vpn: .router)).finding, .downstreamUnknown)
    }

    func testMissingDNSAndUnsupportedEndpointsRemainUnavailable() throws {
        let snapshot = ConnectionDiagnosticsSnapshot(dnsServers: [], services: [
            .desktop: .unavailable("token=private-error"), .code: .observed("2001:db8::7")
        ], checkedAt: date)
        let value = report(diagnostics: .observed(snapshot), services: true)
        XCTAssertEqual(try check(.dnsConfiguration, in: value).status, .unavailable)
        XCTAssertEqual(try check(.desktopEndpoint, in: value).status, .unavailable)
        XCTAssertEqual(try check(.codeEndpoint, in: value).finding, .endpointWithoutComparison)
        let missing = ConnectionDiagnosticsSnapshot(dnsServers: [], services: [:], checkedAt: date)
        XCTAssertEqual(try check(.codeEndpoint, in: report(diagnostics: .observed(missing), services: true)).status, .notChecked)
    }

    func testServiceComparisonSupportsIPv6AndDoesNotCallDifferenceALeak() throws {
        let snapshot = ConnectionDiagnosticsSnapshot(dnsServers: ["192.0.2.53"], services: [
            .desktop: .observed("2001:0db8:0:0:0:0:0:7"), .code: .observed("203.0.113.18")
        ], checkedAt: date)
        let value = report(confirmed: try observation("2001:db8::7"), diagnostics: .observed(snapshot), services: true)
        XCTAssertEqual(try check(.dnsConfiguration, in: value).finding, .configuredDNSOnly)
        XCTAssertEqual(try check(.desktopEndpoint, in: value).finding, .endpointMatches)
        let difference = try check(.codeEndpoint, in: value)
        XCTAssertEqual(difference.status, .attention)
        XCTAssertEqual(difference.finding, .endpointDiffers)
        XCTAssertTrue(difference.finding.detail.contains("не доказательство утечки"))
    }

    func testDiagnosticsExpireAtThirtySecondsAndRejectFutureSnapshots() throws {
        for age in [-1.0, 30.0, 31.0] {
            let snapshot = ConnectionDiagnosticsSnapshot(dnsServers: ["192.0.2.53"],
                                                        services: [.desktop: .observed("203.0.113.17")],
                                                        checkedAt: date.addingTimeInterval(-age))
            let value = report(diagnostics: .observed(snapshot), services: true)
            XCTAssertEqual(try check(.dnsConfiguration, in: value).status, .stale)
            XCTAssertEqual(try check(.desktopEndpoint, in: value).status, .stale)
        }
    }

    func testSleepInvalidatesEveryObservationButPreservesControllerFailure() throws {
        let value = report(confirmed: try observation(), watchdog: true, sleeping: true, protection: .failed("secret"))
        XCTAssertTrue(value.checks.allSatisfy { $0.status == .sleeping })
        XCTAssertEqual(value.controllerState, .failed)
        XCTAssertEqual(try check(.watchdog, in: report(watchdog: false)).status, .attention)
        XCTAssertEqual(try check(.watchdog, in: report(watchdog: true)).finding, .watchdogResponding)
    }

    func testExportDropsRawAddressesErrorsAndSocketMetadataAndFreezesBytes() throws {
        let secret = "token=super-secret https://user:password@private.example /Users/private/file"
        let snapshot = ConnectionDiagnosticsSnapshot(dnsServers: ["192.0.2.53", "2001:db8::53"], services: [
            .desktop: .observed("203.0.113.17"), .code: .unavailable(secret)
        ], checkedAt: date)
        let routes = ClaudeRouteSnapshot(routes: [route()], capturedAt: date)
        let value = report(external: .failed(secret), routes: .observed(routes), diagnostics: .observed(snapshot),
                           services: true, protection: .failed(secret))
        let export = try DiagnosticExport(report: value)
        let text = String(decoding: export.data, as: UTF8.self)
        for excluded in ["203.0.113.17", "10.0.0.7", "192.0.2.53", "2001:db8::53", "utun4", "50000",
                         "super-secret", "password", "private.example", "/Users/", "ESTABLISHED"] {
            XCTAssertFalse(text.contains(excluded), excluded)
        }
        _ = report(external: .checking)
        XCTAssertEqual(export.data, try value.jsonData())
    }

    func testAppReportDoesNotStartReadersChangePolicyOrExportUserText() async throws {
        let domain = "DiagnosticReportTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        let privateText = "private-profile /Users/private token=secret 203.0.113.17"
        let profile = AccessProfile(name: privateText, sharedRules: .init(allowedCountries: ["NL"],
                                                                         allowedIPs: [IPRange("203.0.113.17/32")!]))
        let preferences = AppPreferences(vpnLocation: .router, automaticIPChecks: false,
                                        accessConfiguration: .init(profiles: [profile], activeProfileID: profile.id))
        let journal = EventJournal(events: [.init(title: privateText, detail: privateText)])
        defaults.set(try JSONEncoder().encode(preferences), forKey: "armor.preferences.v1")
        defaults.set(try JSONEncoder().encode(journal), forKey: "armor.journal.v1")
        var externalReads = 0
        var dnsReads = 0
        let monitor = ConnectionDiagnosticsMonitor(now: { self.date }, dns: { dnsReads += 1; return [] })
        let model = AppModel(defaults: defaults, startsMonitoring: false, now: { self.date },
                             diagnosticsReader: { .notChecked }, egressReader: { _ in
            externalReads += 1
            throw EgressError.invalidResponse
        }, connectionDiagnostics: monitor)
        let originalPreferences = model.preferences
        let originalJournal = model.journal
        let originalProtection = model.protection
        for _ in 0..<3 {
            let text = String(decoding: try model.diagnosticReport().jsonData(), as: UTF8.self)
            XCTAssertFalse(text.contains("private"))
            XCTAssertFalse(text.contains("203.0.113.17"))
            XCTAssertFalse(text.contains("token="))
        }
        await Task.yield()
        XCTAssertEqual(externalReads, 0)
        XCTAssertEqual(dnsReads, 0)
        XCTAssertEqual(model.preferences, originalPreferences)
        XCTAssertEqual(model.journal, originalJournal)
        XCTAssertEqual(model.protection, originalProtection)
        XCTAssertEqual(try check(.watchdog, in: model.diagnosticReport()).status, .notChecked)
        model.updateWatchdogHealth(true)
        XCTAssertEqual(try check(.watchdog, in: model.diagnosticReport()).status, .observed)
    }

    func testAppReportUsesActualAdmissionExpiryWithoutWaitingForTimer() async throws {
        var now = date
        let domain = "DiagnosticReportTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        defaults.set(try JSONEncoder().encode(AppPreferences(automaticIPChecks: false, egressProvider: .ipInfo)), forKey: "armor.preferences.v1")
        let observation = try observation()
        let model = AppModel(defaults: defaults, startsMonitoring: false, now: { now },
                             diagnosticsReader: { .notChecked }, egressReader: { _ in observation })
        model.refreshExternalIP()
        for _ in 0..<500 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        XCTAssertEqual(try check(.egress, in: model.diagnosticReport()).status, .observed)
        let preview = try DiagnosticExport(report: model.diagnosticReport())
        now += 60
        XCTAssertEqual(try check(.egress, in: model.diagnosticReport()).status, .stale)
        XCTAssertEqual(try check(.egress, in: preview.report).status, .observed, "An opened preview is a frozen snapshot")
        model.prepareForSleep()
        XCTAssertTrue(model.diagnosticReport().checks.allSatisfy { $0.status == .sleeping })
    }
}
