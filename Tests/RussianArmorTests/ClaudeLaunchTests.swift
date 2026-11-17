import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class ClaudeLaunchTests: XCTestCase {
    private func defaults() throws -> UserDefaults {
        let name = "ClaudeLaunchTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        addTeardownBlock { defaults.removePersistentDomain(forName: name) }
        defaults.set(
            try JSONEncoder().encode(AppPreferences(allowedCountryCode: "SE")),
            forKey: "armor.preferences.v1"
        )
        return defaults
    }

    private func observation(_ provider: EgressProvider) throws -> EgressObservation {
        let json = provider == .ipWhoIS
            ? #"{"success":true,"ip":"203.0.113.7","country_code":"SE"}"#
            : #"{"ip":"203.0.113.7","country":"FI"}"#
        return try EgressObservation.decode(Data(json.utf8), provider: provider)
    }

    private func settle(_ model: AppModel) async {
        for _ in 0..<300 {
            if !model.externalCheck.isChecking { return }
            await Task.yield()
        }
        XCTFail("Egress check did not settle")
    }

    private func protectedModel(
        launcher: @escaping () async throws -> Void
    ) throws -> AppModel {
        let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
        return AppModel(
            defaults: try defaults(), startsMonitoring: false, automaticCheckDelay: 0,
            diagnosticsReader: {
                LocalDiagnosticsSnapshot(
                    tunnels: .observed([]), claudeDesktop: .notRunning, checkedAt: Date()
                )
            },
            egressReader: { try self.observation($0) },
            processProtection: controller,
            claudeLauncher: launcher
        )
    }

    func testLaunchRequiresFreshAllowedCountryAndRecordsControlledStart() async throws {
        var launches = 0
        let model = try protectedModel { launches += 1 }
        XCTAssertFalse(model.canLaunchClaudeUnderProtection)

        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        XCTAssertEqual(model.protection, .countryConfirmed)
        XCTAssertTrue(model.canLaunchClaudeUnderProtection)

        try await model.launchClaudeUnderProtection()
        XCTAssertEqual(launches, 1)
        XCTAssertTrue(model.journal.events.contains { $0.title == "Claude запущен под контролем" })
    }

    func testLaunchIsRejectedBeforeProtectionBecomesOperational() async throws {
        var launches = 0
        let model = try protectedModel { launches += 1 }
        do {
            try await model.launchClaudeUnderProtection()
            XCTFail("Unconfirmed country must not launch Claude")
        } catch {
            XCTAssertEqual(error as? ClaudeSafeLaunchError, .protectionUnavailable)
        }
        XCTAssertEqual(launches, 0)
    }

    func testNetworkChangeDuringLaunchPausesClaudeAndReportsFailure() async throws {
        var pending: CheckedContinuation<Void, Error>?
        let model = try protectedModel {
            try await withCheckedThrowingContinuation { pending = $0 }
        }
        model.receive(NetworkSnapshot(connectivity: .available))
        await settle(model)
        XCTAssertTrue(model.canLaunchClaudeUnderProtection)

        let launch = Task { try await model.launchClaudeUnderProtection() }
        for _ in 0..<300 {
            if pending != nil { break }
            await Task.yield()
        }
        let continuation = try XCTUnwrap(pending)
        model.receive(NetworkSnapshot(connectivity: .unavailable))
        continuation.resume(returning: ())
        do {
            try await launch.value
            XCTFail("Changed network must invalidate the launch")
        } catch {
            XCTAssertEqual(error as? ClaudeSafeLaunchError, .protectionChanged)
        }
        XCTAssertFalse(model.protection.isOperational)
        XCTAssertFalse(model.canLaunchClaudeUnderProtection)
    }
}
