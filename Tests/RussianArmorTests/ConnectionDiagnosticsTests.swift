import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class ConnectionDiagnosticsTests: XCTestCase {
    private func settle(_ monitor: ConnectionDiagnosticsMonitor) async {
        for _ in 0..<500 {
            if monitor.state != .checking { return }
            await Task.yield()
        }
        XCTFail("Diagnostics did not settle")
    }

    func testAppWakeResumesDiagnosticsOnSameNetworkEvenWhenEgressFails() async throws {
        let domain = "ConnectionDiagnosticsTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        defaults.set(try JSONEncoder().encode(AppPreferences(automaticIPChecks: true)),
                     forKey: "armor.preferences.v1")
        var dnsReads = 0
        var egressReads = 0
        let monitor = ConnectionDiagnosticsMonitor(dns: {
            dnsReads += 1
            return ["192.0.2.53"]
        })
        let model = AppModel(defaults: defaults, startsMonitoring: false, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: { _ in
            egressReads += 1
            throw EgressError.invalidResponse
        }, connectionDiagnostics: monitor)
        let network = NetworkSnapshot(connectivity: .available)
        model.receive(network)
        await settle(monitor)
        for _ in 0..<500 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        XCTAssertEqual(dnsReads, 1)
        XCTAssertEqual(egressReads, 1)
        model.prepareForSleep()
        XCTAssertEqual(monitor.state, .sleeping)
        model.resumeAfterWake()
        model.receive(network)
        await settle(monitor)
        for _ in 0..<500 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        guard case .observed(let snapshot) = monitor.state else {
            return XCTFail("DNS diagnostics must resume independently of egress verification")
        }
        XCTAssertEqual(snapshot.dnsServers, ["192.0.2.53"])
        XCTAssertEqual(dnsReads, 2)
        XCTAssertEqual(egressReads, 2)
        guard case .failed = model.externalCheck else { return XCTFail("Egress unexpectedly succeeded") }
    }

    func testServiceRequestsRequireOptInAndRepeatOnlyAfterFifteenSeconds() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        var requests: [ServiceProbe] = []
        var dnsReads = 0
        let monitor = ConnectionDiagnosticsMonitor(now: { date }, probe: {
            requests.append($0); return "203.0.113.7"
        }, dns: { dnsReads += 1; return ["192.0.2.53"] })
        monitor.tick(online: true, servicesEnabled: false)
        await settle(monitor)
        XCTAssertTrue(requests.isEmpty)
        XCTAssertEqual(dnsReads, 1)
        monitor.tick(online: true, servicesEnabled: true)
        await settle(monitor)
        XCTAssertEqual(requests, [.desktop, .code])
        date += 14
        monitor.tick(online: true, servicesEnabled: true)
        await Task.yield()
        XCTAssertEqual(requests.count, 2)
        date += 1
        monitor.tick(online: true, servicesEnabled: true)
        await settle(monitor)
        XCTAssertEqual(requests, [.desktop, .code, .desktop, .code])
    }

    func testSleepAndDisableDiscardLateResultsAndNoRequestOverlaps() async throws {
        var pending: CheckedContinuation<String, Error>?
        var requests = 0
        let monitor = ConnectionDiagnosticsMonitor(probe: { _ in
            requests += 1
            return try await withCheckedThrowingContinuation { pending = $0 }
        }, dns: { [] })
        monitor.tick(online: true, servicesEnabled: true)
        for _ in 0..<500 { if pending != nil { break }; await Task.yield() }
        let continuation = try XCTUnwrap(pending)
        for _ in 0..<10 { monitor.tick(online: true, servicesEnabled: true) }
        XCTAssertEqual(requests, 1)
        monitor.invalidate(sleeping: true)
        continuation.resume(returning: "203.0.113.7")
        for _ in 0..<30 { await Task.yield() }
        XCTAssertEqual(monitor.state, .sleeping)
        XCTAssertEqual(requests, 1, "A cancelled result cannot trigger another endpoint")
        monitor.tick(online: true, servicesEnabled: false)
        XCTAssertEqual(monitor.state, .sleeping)
        monitor.invalidate()
        monitor.tick(online: true, servicesEnabled: false)
        await settle(monitor)
        guard case .observed(let snapshot) = monitor.state else { return XCTFail("DNS result missing") }
        XCTAssertTrue(snapshot.services.isEmpty)
        XCTAssertEqual(requests, 1)
    }

    func testRetryAfterSurvivesNetworkChangesAndToggles() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        let retry = date.addingTimeInterval(1000)
        var requests = 0
        let monitor = ConnectionDiagnosticsMonitor(now: { date }, probe: { _ in
            requests += 1
            throw ServiceProbeFailure(retryAt: retry)
        }, dns: { [] })
        monitor.tick(online: true, servicesEnabled: true)
        await settle(monitor)
        XCTAssertEqual(requests, 2)
        for _ in 0..<3 {
            date += 15
            monitor.invalidate()
            monitor.tick(online: true, servicesEnabled: false)
            await settle(monitor)
            monitor.tick(online: true, servicesEnabled: true)
            await settle(monitor)
        }
        XCTAssertEqual(requests, 2)
        date = retry
        monitor.tick(online: true, servicesEnabled: true)
        await settle(monitor)
        XCTAssertEqual(requests, 4)
    }

    func testHungDiagnosticsBecomeStaleAndLateAnswerIsIgnored() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        var pending: CheckedContinuation<String, Error>?
        let monitor = ConnectionDiagnosticsMonitor(now: { date }, probe: { _ in
            try await withCheckedThrowingContinuation { pending = $0 }
        }, dns: { [] })
        monitor.tick(online: true, servicesEnabled: true)
        for _ in 0..<500 { if pending != nil { break }; await Task.yield() }
        let continuation = try XCTUnwrap(pending)
        date += 20
        monitor.tick(online: true, servicesEnabled: true)
        XCTAssertEqual(monitor.state, .stale)
        continuation.resume(returning: "203.0.113.7")
        for _ in 0..<30 { await Task.yield() }
        XCTAssertEqual(monitor.state, .stale)
    }

    func testTraceParserAcceptsOnlyOneLiteralIPAndIgnoresLocation() throws {
        XCTAssertEqual(try ServiceProbeReader.decode(Data("ip=2001:db8::7\nloc=RU\n".utf8)), "2001:db8::7")
        for text in ["<html>challenge</html>", "ip=hostname\n", "ip=192.0.2.1\nip=192.0.2.2\n",
                     "ip=192.0.2.1/24\n", "ip=fe80::1%en0\n", "ip=192.0.2.1\0\n"] {
            XCTAssertThrowsError(try ServiceProbeReader.decode(Data(text.utf8)))
        }
        XCTAssertThrowsError(try ServiceProbeReader.decode(Data(repeating: 65, count: 4097)))
    }

    func testDNSConfigurationIsDeduplicatedAndDoesNotIncludeDomains() {
        let values: [String: [String: Any]] = [
            "global": ["ServerAddresses": ["192.0.2.53", "invalid"], "SearchDomains": ["private.example"]],
            "service": ["ServerAddresses": ["192.0.2.53", "2001:db8::53"]]
        ]
        XCTAssertEqual(DNSConfigurationReader.addresses(in: values), ["192.0.2.53", "2001:db8::53"])
    }

    func testComparisonRequiresFreshAdmissionAndDoesNotClaimLeakProof() {
        XCTAssertTrue(ConnectionDiagnosticsView.comparison("192.0.2.1", expectedIP: nil).contains("Нет свежего"))
        XCTAssertTrue(ConnectionDiagnosticsView.comparison("2001:db8::1", expectedIP: "2001:0db8:0:0:0:0:0:1").contains("совпадает"))
        XCTAssertTrue(ConnectionDiagnosticsView.comparison("192.0.2.1", expectedIP: "192.0.2.2").contains("не доказательство"))
    }

    func testOldPreferencesDoNotEnableUndocumentedServiceProbes() throws {
        let old = Data(#"{"showInterfaceNames":true}"#.utf8)
        let preferences = try JSONDecoder().decode(AppPreferences.self, from: old)
        XCTAssertFalse(preferences.serviceDiagnosticsEnabled)
        XCTAssertFalse(AppPreferences().serviceDiagnosticsEnabled)
        let configured = AppPreferences(serviceDiagnosticsEnabled: true)
        XCTAssertEqual(try JSONDecoder().decode(AppPreferences.self, from: JSONEncoder().encode(configured)), configured)
    }
}
