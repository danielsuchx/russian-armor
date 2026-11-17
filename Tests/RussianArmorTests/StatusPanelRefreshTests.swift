import AppKit
import ArmorCore
import Foundation
import XCTest
@testable import RussianArmor

@MainActor
final class StatusPanelRefreshTests: XCTestCase {
    @MainActor
    private final class Fixture {
        let suite = "StatusPanelRefresh.\(UUID().uuidString)"
        let defaults: UserDefaults
        var instant = Date()
        var holdNextRead = false
        var pending: CheckedContinuation<EgressObservation, Error>?
        var pendingProvider: EgressProvider?
        var model: AppModel!

        init() throws {
            defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
            defaults.set(try JSONEncoder().encode(AppPreferences(allowedCountryCode: "NL")), forKey: "armor.preferences.v1")
            let controller = ProcessProtectionController(automaticallyMonitor: false, processReader: { [] })
            model = AppModel(defaults: defaults, startsMonitoring: false, now: { [unowned self] in instant },
                             diagnosticsReader: { .notChecked }, egressReader: { [unowned self] provider in
                if holdNextRead {
                    holdNextRead = false
                    pendingProvider = provider
                    return try await withCheckedThrowingContinuation { pending = $0 }
                }
                return try observation(provider: provider)
            }, processProtection: controller)
        }
        func observation(provider: EgressProvider) throws -> EgressObservation {
            let json = provider == .ipWhoIS
                ? #"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#
                : #"{"ip":"203.0.113.7","country":"NL"}"#
            return try .decode(Data(json.utf8), provider: provider)
        }
        func finish() {
            model.prepareForSleep()
            pending?.resume(throwing: CancellationError()); pending = nil
            defaults.removePersistentDomain(forName: suite)
        }
        func complete(_ error: Error? = nil) throws {
            let continuation = try XCTUnwrap(pending)
            pending = nil
            if let error { continuation.resume(throwing: error) }
            else { continuation.resume(returning: try observation(provider: XCTUnwrap(pendingProvider))) }
        }
    }

    private func waitFor(_ condition: () -> Bool) async {
        for _ in 0..<1000 { if condition() { return }; await Task.yield() }
        XCTFail("Fixture did not reach the expected transition")
    }

    func testPlannedRefreshKeepsConfirmedFieldsStatusAndProviderDetails() async throws {
        let fixture = try Fixture()
        defer { fixture.finish() }
        fixture.model.refreshExternalIP()
        let initial = StatusPanelContent(model: fixture.model)
        XCTAssertEqual(initial.diagnosticsSummary, "Подтверждаем подключение · Claude на паузе")
        XCTAssertFalse(fixture.model.protection.isOperational)
        await waitFor { !fixture.model.externalCheck.isChecking }
        let before = StatusPanelContent(model: fixture.model)
        XCTAssertEqual(before.diagnosticsSummary, "Подключение подтверждено")
        XCTAssertTrue(fixture.model.protection.isOperational)
        let comparison = fixture.model.countryComparison

        fixture.instant += ProtectionTiming.checkInterval
        fixture.holdNextRead = true
        fixture.model.refreshExternalIP()
        await waitFor { fixture.pending != nil }
        let during = StatusPanelContent(model: fixture.model)
        XCTAssertEqual(during.country, before.country)
        XCTAssertEqual(during.ip, before.ip)
        XCTAssertEqual(during.protection, before.protection)
        XCTAssertEqual(during.diagnosticsSummary, before.diagnosticsSummary)
        XCTAssertEqual(fixture.model.countryComparison, comparison)
        XCTAssertTrue(during.externalDetail.contains("Обновляем данные в фоне"))
        XCTAssertTrue(during.externalDetail.contains("страна подтверждена обоими сервисами"))
        XCTAssertTrue(fixture.model.protection.isOperational)
        try fixture.complete()
        await waitFor { !fixture.model.externalCheck.isChecking }
        let after = StatusPanelContent(model: fixture.model)
        XCTAssertEqual(after.diagnosticsSummary, before.diagnosticsSummary)
        XCTAssertFalse(after.externalDetail.contains("Обновляем данные в фоне"))
    }

    func testRefreshFailureReplacesPreviousSuccessAndPausesClaude() async throws {
        let fixture = try Fixture()
        defer { fixture.finish() }
        fixture.model.refreshExternalIP()
        await waitFor { !fixture.model.externalCheck.isChecking }
        fixture.instant += ProtectionTiming.checkInterval
        fixture.holdNextRead = true
        fixture.model.refreshExternalIP()
        await waitFor { fixture.pending != nil }
        try fixture.complete(URLError(.secureConnectionFailed))
        await waitFor { !fixture.model.externalCheck.isChecking }
        let content = StatusPanelContent(model: fixture.model)
        XCTAssertFalse(fixture.model.protection.isOperational)
        XCTAssertEqual(content.country, "Не определена")
        XCTAssertEqual(content.ip, "Ошибка проверки…")
        XCTAssertEqual(content.diagnosticsAction, .failureDetails)
        XCTAssertEqual(content.diagnosticsSummary, "Подключение не подтверждено · Claude на паузе")
        XCTAssertNil(fixture.model.confirmedEgressObservation)
    }

    func testExpiredLeaseDuringRefreshDoesNotKeepOldFieldsOrConfirmedStatus() async throws {
        let fixture = try Fixture()
        defer { fixture.finish() }
        fixture.model.refreshExternalIP()
        await waitFor { !fixture.model.externalCheck.isChecking }
        fixture.instant += ProtectionTiming.checkInterval
        fixture.holdNextRead = true
        fixture.model.refreshExternalIP()
        await waitFor { fixture.pending != nil }
        fixture.instant += ProtectionTiming.confirmationLifetime - ProtectionTiming.checkInterval
        fixture.model.expireExternalCheck()
        let content = StatusPanelContent(model: fixture.model)
        XCTAssertEqual(content.country, "Проверяется…")
        XCTAssertEqual(content.ip, "Проверяется…")
        XCTAssertEqual(content.diagnosticsSummary, "Подтверждаем подключение · Claude на паузе")
        XCTAssertFalse(content.externalDetail.contains("прежнее подтверждение ещё действует"))
        XCTAssertFalse(fixture.model.protection.isOperational)
        XCTAssertNil(fixture.model.confirmedEgressObservation)
    }

    func testLivePanelKeepsItsFrameAndFieldsAcrossPlannedRefresh() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOR_RENDER_REFRESH_TESTS"] == "1", "Opt-in live refresh rendering")
        _ = NSApplication.shared
        let fixture = try Fixture()
        defer { fixture.finish() }
        fixture.model.refreshExternalIP()
        await waitFor { !fixture.model.externalCheck.isChecking }
        let panel = StatusPanelController(model: fixture.model) { _ in }
        defer { panel.close() }
        let screen = try XCTUnwrap(NSScreen.main).visibleFrame
        panel.show(anchor: NSRect(x: screen.midX, y: screen.maxY, width: 24, height: 24), visibleFrame: screen)
        try await Task.sleep(nanoseconds: 200_000_000)
        let before = panel.window.frame
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("armor-refresh-render-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        func capture(_ name: String) throws {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            let target = directory.appendingPathComponent(name + ".png")
            process.arguments = ["-x", "-o", "-l\(panel.window.windowNumber)", target.path]
            try process.run(); process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
            print("REFRESH_PANEL_\(name.uppercased()): \(target.path)")
        }
        try capture("before")
        fixture.instant += ProtectionTiming.checkInterval
        fixture.holdNextRead = true
        fixture.model.refreshExternalIP()
        await waitFor { fixture.pending != nil }
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(panel.window.frame, before)
        XCTAssertEqual(StatusPanelContent(model: fixture.model).diagnosticsSummary, "Подключение подтверждено")
        try capture("during")
        try fixture.complete(URLError(.secureConnectionFailed))
        await waitFor { !fixture.model.externalCheck.isChecking }
        try await Task.sleep(nanoseconds: 200_000_000)
        try capture("failure")
    }

    func testSleepInvalidatesDisplayedConfirmationAndRejectsLateRefreshResult() async throws {
        let fixture = try Fixture()
        defer { fixture.finish() }
        fixture.model.refreshExternalIP()
        await waitFor { !fixture.model.externalCheck.isChecking }
        fixture.instant += ProtectionTiming.checkInterval
        fixture.holdNextRead = true
        fixture.model.refreshExternalIP()
        await waitFor { fixture.pending != nil }
        fixture.model.prepareForSleep()
        try fixture.complete()
        for _ in 0..<20 { await Task.yield() }
        let content = StatusPanelContent(model: fixture.model)
        XCTAssertEqual(content.country, "Проверка приостановлена")
        XCTAssertEqual(content.diagnosticsSummary, "Проверки приостановлены до пробуждения")
        XCTAssertFalse(fixture.model.protection.isOperational)
        XCTAssertNil(fixture.model.confirmedEgressObservation)
    }
}
