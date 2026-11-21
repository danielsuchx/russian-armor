import ArmorCore
import AppKit
import Foundation
import Combine
import XCTest
@testable import RussianArmor

private actor NativeCommandLog {
    private(set) var calls: [(String, [String: EngineValue])] = []
    var resolves = false
    func setResolves(_ value: Bool) { resolves = value }
    func call(_ command: String, args: [String: EngineValue]) throws -> EngineValue {
        calls.append((command, args))
        switch command {
        case "native_poll_events": return .array([])
        case "take_pending_alert": return .null
        case "get_sysproxy_status", "check_cli_protection_status": return .bool(false)
        case "resolve_interception": return .bool(resolves)
        case "native_shutdown": return .bool(true)
        default: return .object([:])
        }
    }
}

@MainActor
final class NetworkEngineTests: XCTestCase {
    private func defaults() throws -> UserDefaults {
        let domain = "NetworkEngineTests.\(UUID().uuidString)"
        let values = try XCTUnwrap(UserDefaults(suiteName: domain))
        addTeardownBlock { values.removePersistentDomain(forName: domain) }
        return values
    }
    private func wait(_ condition: () -> Bool) async {
        for _ in 0..<1000 { if condition() { return }; await Task.yield() }
        XCTFail("Native action did not settle")
    }

    func testProtocolPreservesTypesAndDoesNotCoerceUnknownStatusToSuccess() throws {
        let value = try JSONDecoder().decode(EngineValue.self, from: Data(#"{"ok":false,"value":{"status":"unexpected"},"count":3,"missing":null}"#.utf8))
        XCTAssertFalse(value["ok"].bool)
        XCTAssertEqual(value["value"]["status"].string, "unexpected")
        XCTAssertFalse(value["value"]["status"].bool)
        XCTAssertEqual(value["count"].number, 3)
        XCTAssertEqual(value["missing"], .null)
        XCTAssertEqual(try JSONDecoder().decode(EngineValue.self, from: JSONEncoder().encode(value)), value)
    }

    func testOpeningNativeModuleDoesNotEnableProxiesOrRunAudits() async throws {
        let log = NativeCommandLog()
        let store = NetworkEngineStore(defaults: try defaults(), transport: { try await log.call($0, args: $1) })
        await store.refresh()
        let commands = await log.calls.map(\.0)
        XCTAssertTrue(commands.contains("get_state"))
        XCTAssertTrue(commands.contains("get_coverage_snapshot"))
        XCTAssertFalse(commands.contains("toggle_sysproxy"))
        XCTAssertFalse(commands.contains("enable_cli_protection"))
        XCTAssertFalse(commands.contains("audit_connection"))
        XCTAssertFalse(store.sysproxy)
        XCTAssertFalse(store.cliEnabled)
    }

    func testUnchangedPollingKeepsHeartbeatWithoutPublishingRedundantUIUpdates() async throws {
        let log = NativeCommandLog()
        let store = NetworkEngineStore(defaults: try defaults(), transport: { try await log.call($0, args: $1) })
        await store.refresh()
        var notifications = 0
        let subscription = store.objectWillChange.sink { notifications += 1 }
        defer { subscription.cancel() }
        await store.refresh()
        await store.refresh(includeDetails: false)
        XCTAssertEqual(notifications, 0)
        XCTAssertTrue(store.isHealthy)
        let heartbeatCalls = await log.calls.filter { $0.0 == "get_state" }.count
        XCTAssertEqual(heartbeatCalls, 3,
                       "Heartbeat checks must continue even when the UI has no changes")
        store.receiveEvent(.object(["name": .string("interceptor://risk-detected"),
                                    "payload": .object(["id": .string("risk")])]))
        XCTAssertGreaterThan(notifications, 0, "A real alert must still reach the UI")
    }

    func testOnlyMatchingAlertCanBeEnrichedAndResolved() throws {
        let store = NetworkEngineStore(defaults: try defaults())
        store.receiveEvent(.object(["name": .string("interceptor://risk-detected"), "payload": .object(["id": .string("first"), "phase": .string("detecting")])]))
        store.receiveEvent(.object(["name": .string("interceptor://enriched"), "payload": .object(["id": .string("other"), "phase": .string("ready")])]))
        XCTAssertEqual(store.pendingAlert["phase"].string, "detecting")
        store.receiveEvent(.object(["name": .string("interceptor://enriched"), "payload": .object(["id": .string("first"), "phase": .string("ready")])]))
        XCTAssertEqual(store.pendingAlert["phase"].string, "ready")
        store.receiveEvent(.object(["name": .string("interceptor://resolved"), "payload": .string("")]))
        XCTAssertEqual(store.pendingAlert, .null)
    }

    func testRefusedAllowKeepsAlertAndUsesItsOriginalScope() async throws {
        let log = NativeCommandLog()
        let store = NetworkEngineStore(defaults: try defaults(), transport: { try await log.call($0, args: $1) })
        let alert: EngineValue = .object(["id": .string("hold"), "provider": .string("anthropic"), "scope": .string("network"), "phase": .string("ready")])
        store.receiveEvent(.object(["name": .string("interceptor://risk-detected"), "payload": alert]))
        store.resolveAlert("allowSession")
        await wait { !store.busy.contains("resolve_interception") }
        XCTAssertEqual(store.pendingAlert, alert)
        XCTAssertNotNil(store.error)
        let arguments = await log.calls.first { $0.0 == "resolve_interception" }?.1
        XCTAssertEqual(arguments?["scope"], .string("network"))
    }

    func testLostHelperRevokesDisplayedState() async throws {
        let store = NetworkEngineStore(defaults: try defaults(), transport: { _, _ in throw NetworkEngineError.unavailable })
        XCTAssertTrue(store.connected)
        await store.refresh()
        XCTAssertFalse(store.connected)
        XCTAssertFalse(store.sysproxy)
        XCTAssertFalse(store.cliEnabled)
        XCTAssertTrue(store.reports.isEmpty)
    }

    func testHideAddressesWorksOfflineAndDoesNotChangeActualObservation() throws {
        let values = try defaults()
        let store = NetworkEngineStore(defaults: values)
        store.setHideIP(true)
        XCTAssertTrue(store.hideIP)
        XCTAssertTrue(values.bool(forKey: "armor.privacy.hideIP"))
        let raw = "203.0.113.9:443 / 2001:db8::9 / 10.0.0.0/8"
        let masked = store.display(raw)
        for ip in ["203.0.113.9", "2001:db8::9", "10.0.0.0"] { XCTAssertFalse(masked.contains(ip)) }
        store.setHideIP(false)
        XCTAssertEqual(store.display(raw), raw)
    }

    func testErrorsDoNotRevealCredentialsOrUserPaths() {
        let value = EngineValue.string("Failed socks5://user:password@203.0.113.9:1080 token=secret /Users/private/key at 2001:db8::7")
        let text = NetworkEngineError.rejected(value).localizedDescription
        for secret in ["password", "203.0.113.9", "secret", "/Users/private", "2001:db8::7"] {
            XCTAssertFalse(text.contains(secret))
        }
    }

    func testSessionTokenIsPrivateStableAndRejectsSymlink() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-ipc-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = try NetworkEngineClient.makeSession(in: directory)
        let second = try NetworkEngineClient.makeSession(in: directory)
        XCTAssertEqual(first.token, second.token)
        XCTAssertTrue(NetworkEngineClient.validToken(first.token))
        let permissions = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("session").path)[.posixPermissions] as? NSNumber)
        XCTAssertEqual(permissions.intValue & 0o777, 0o600)
        try FileManager.default.removeItem(at: directory.appendingPathComponent("session"))
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("session"), withDestinationURL: directory.appendingPathComponent("foreign"))
        XCTAssertThrowsError(try NetworkEngineClient.makeSession(in: directory))
        XCTAssertFalse(NetworkEngineClient.validToken(String(repeating: "x", count: 64)))
    }

    func testUnavailableRequiredGatewayKeepsClaudePausedDespiteFreshCountry() async throws {
        let values = try defaults()
        values.set(true, forKey: "armor.network.enabled")
        values.set(true, forKey: "armor.network.cli")
        values.set(try JSONEncoder().encode(AppPreferences(vpnLocation: .router, automaticIPChecks: false, allowedCountryCode: "NL")),
                   forKey: "armor.preferences.v1")
        let engine = NetworkEngineStore(defaults: values, transport: { _, _ in throw NetworkEngineError.unavailable })
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        let model = AppModel(defaults: values, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { provider in
            let payload = provider == .ipWhoIS ? #"{"ip":"203.0.113.1","country_code":"NL","success":true}"# : #"{"ip":"203.0.113.1","country":"NL"}"#
            return try EgressObservation.decode(Data(payload.utf8), provider: provider)
        }, processProtection: controller, recoverySuccesses: 1, networkEngine: engine)
        defer { model.shutdownProtection() }
        model.refreshExternalIP()
        await wait { !model.externalCheck.isChecking }
        XCTAssertEqual(model.protection, .countryConfirmed)
        await engine.refresh()
        model.expireExternalCheck()
        XCTAssertNotEqual(model.protection, .countryConfirmed)
        XCTAssertTrue(model.protection.detail.contains("Сетевой шлюз недоступен"))
        XCTAssertFalse(model.canLaunchClaudeUnderProtection)
    }

    func testNativeClientExchangesMessagesWithDebugHelperWithoutOSChanges() async throws {
        guard let binary = ProcessInfo.processInfo.environment["ARMOR_ENGINE_IPC_TEST_BINARY"] else {
            throw XCTSkip("Opt-in debug helper IPC test")
        }
        let directory = URL(fileURLWithPath: "/private/tmp/ra-ipc-swift-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let client = try NetworkEngineClient.makeSession(in: directory)
        let child = Process()
        child.executableURL = URL(fileURLWithPath: binary)
        child.arguments = ["--native-bridge", client.socket, "--native-smoke-test", "--minimized"]
        child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
        try child.run()
        defer { if child.isRunning { child.terminate() } }
        var ping: EngineValue?
        for _ in 0..<100 {
            ping = try? await client.call("native_ping")
            if ping != nil { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(ping?["protocol"].number, 1)
        let application = try XCTUnwrap(NSRunningApplication(processIdentifier: child.processIdentifier))
        for _ in 0..<100 {
            if application.isFinishedLaunching { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertTrue(application.isFinishedLaunching)
        XCTAssertEqual(application.activationPolicy, .accessory, "The network helper must stay out of the Dock and app switcher")
        _ = try await client.call("get_state")
        do { _ = try await client.call("toggle_sysproxy", ["enable": .bool(true)]); XCTFail("Smoke tests must refuse OS changes") }
        catch { XCTAssertNotNil((error as? NetworkEngineError)?.errorDescription) }
        _ = try await client.call("native_shutdown")
        for _ in 0..<100 { if !child.isRunning { break }; try await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertFalse(child.isRunning)
    }
}
