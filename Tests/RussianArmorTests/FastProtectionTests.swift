import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class FastProtectionTests: XCTestCase {
    private var domains: [String] = []
    override func tearDown() {
        for name in domains { UserDefaults(suiteName: name)?.removePersistentDomain(forName: name) }
        super.tearDown()
    }
    private func storage() throws -> UserDefaults {
        let name = "FastProtectionTests.\(UUID().uuidString)"
        domains.append(name)
        let defaults = UserDefaults(suiteName: name)!
        defaults.set(try JSONEncoder().encode(AppPreferences(allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
        return defaults
    }
    private func response(_ provider: EgressProvider) throws -> EgressObservation {
        let body: [String: Any] = provider == .ipWhoIS
            ? ["success": true, "ip": "203.0.113.7", "country_code": "NL"]
            : ["ip": "203.0.113.7", "country": "NL"]
        return try .decode(JSONSerialization.data(withJSONObject: body), provider: provider)
    }
    private func settle(_ model: AppModel) async {
        for _ in 0..<500 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("Check did not settle")
    }
    private func controller() -> ProcessProtectionController {
        ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
    }

    func testProtectedModeRefreshesAtFiveSecondsWithoutRevokingFreshPermission() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        var requests = 0
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests += 1; return try self.response($0)
        }, processProtection: controller())
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        date += 4
        model.expireExternalCheck()
        await Task.yield()
        XCTAssertEqual(requests, 2)
        date += 1
        model.expireExternalCheck()
        XCTAssertTrue(model.externalCheck.isChecking)
        XCTAssertTrue(model.protection.isOperational)
        await settle(model)
        XCTAssertEqual(requests, 4)
        XCTAssertTrue(model.protection.isOperational)
    }

    func testHungRefreshCannotExtendFifteenSecondLease() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        var requests = 0
        var pending: CheckedContinuation<EgressObservation, Error>?
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: { provider in
            requests += 1
            if requests <= 2 { return try self.response(provider) }
            return try await withCheckedThrowingContinuation { pending = $0 }
        }, processProtection: controller())
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        date += 5
        model.expireExternalCheck()
        for _ in 0..<500 { if pending != nil { break }; await Task.yield() }
        let continuation = try XCTUnwrap(pending)
        date += 9
        model.expireExternalCheck()
        XCTAssertTrue(model.protection.isOperational)
        date += 1
        model.expireExternalCheck()
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertNil(model.confirmedEgressObservation)
        XCTAssertTrue(model.externalCheck.isChecking, "Expiry must not start overlapping requests")
        XCTAssertEqual(requests, 3)
        model.prepareForSleep()
        continuation.resume(returning: try response(.ipWhoIS))
        for _ in 0..<30 { await Task.yield() }
        XCTAssertFalse(model.protection.isOperational, "A cancelled generation cannot restore permission")
        XCTAssertEqual(requests, 3)
    }

    func testFailurePausesImmediatelyAndRetriesAfterFiveSeconds() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        var fail = false
        var requests = 0
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: {
            requests += 1
            if fail { throw EgressError.invalidResponse }
            return try self.response($0)
        }, processProtection: controller())
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        fail = true
        date += 5
        model.expireExternalCheck()
        await settle(model)
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertNil(model.confirmedEgressObservation)
        fail = false
        date += 4
        model.expireExternalCheck()
        await Task.yield()
        XCTAssertEqual(requests, 3)
        date += 1
        model.expireExternalCheck()
        await settle(model)
        XCTAssertEqual(requests, 5)
        XCTAssertTrue(model.protection.isOperational)
    }

    func testRecoveryStillRequiresThreeSpacedSuccesses() async throws {
        var date = Date(timeIntervalSince1970: 1000)
        let model = AppModel(defaults: try storage(), startsMonitoring: false, now: { date }, automaticCheckDelay: 0,
                             diagnosticsReader: { .notChecked }, egressReader: { try self.response($0) },
                             processProtection: controller(), recoverySuccesses: 3)
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        XCTAssertFalse(model.protection.isOperational)
        model.refreshExternalIP()
        await settle(model)
        XCTAssertFalse(model.protection.isOperational, "Repeated manual requests cannot accelerate recovery")
        date += 2
        model.expireExternalCheck()
        await settle(model)
        XCTAssertFalse(model.protection.isOperational)
        date += 2
        model.expireExternalCheck()
        await settle(model)
        XCTAssertTrue(model.protection.isOperational)
        XCTAssertEqual(model.recoveryProgress, "3 из 3 успешных проверок")
    }
}
