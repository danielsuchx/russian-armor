import AppKit
import Foundation
import XCTest
import ArmourCore
@testable import RussianArmour

@MainActor
final class NativeMenuTests: XCTestCase {
    private func makeModel(defaults: UserDefaults) -> AppModel {
        AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: {
            LocalDiagnosticsSnapshot(tunnels: .observed([]), claudeDesktop: .running, checkedAt: Date())
        })
    }

    func testMenuUsesOnlySystemRowsWithoutCustomViews() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        XCTAssertTrue(controller.menu.items.allSatisfy { $0.view == nil })
        XCTAssertEqual(controller.menu.font.pointSize, 13)
        let header = try XCTUnwrap(controller.menu.items.first)
        XCTAssertEqual(header.title, "Защита не настроена")
        XCTAssertLessThanOrEqual(try XCTUnwrap(header.image).size.height, 12)
        XCTAssertFalse(header.title.contains(":"), "Header must not include a clock")
        XCTAssertFalse(header.isEnabled)
    }

    func testStatusFieldsAndActionsHaveNativeSymbolImages() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        let titles = [
            "Защита не настроена", "Страна: Не проверена", "VPN: Не указано", "IP: Не проверен",
            "IPv6: утечки не проверены", "Claude: открыт", "Защита: трафик не блокируется",
            "Вся история…", "Перепроверить", "Проверить IP и страну…",
            "Что нужно для защиты?", "Сетевые соединения…", "Соединения: Наблюдение выключено",
            "Настройки…", "Выйти из Russian Armour"
        ]
        for title in titles {
            let item = try XCTUnwrap(controller.menu.items.first { $0.title == title }, title)
            let image = try XCTUnwrap(item.image, title)
            XCTAssertTrue(image.isTemplate, title)
            XCTAssertGreaterThan(image.size.width, 0, title)
            XCTAssertGreaterThan(image.size.height, 0, title)
            XCTAssertLessThanOrEqual(max(image.size.width, image.size.height), 14.01, title)
            XCTAssertNotNil(image.cgImage(forProposedRect: nil, context: nil, hints: nil), title)
            XCTAssertNil(item.view, title)
        }
    }

    func testSleepAndWakeEventsKeepTheirSymbolsOnUpdate() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        model.prepareForSleep()
        XCTAssertEqual(model.journal.events.first?.kind, .sleep)
        model.resumeAfterWake()
        XCTAssertEqual(model.journal.events.first?.kind, .wake)
        controller.updateContents()
        for title in ["Mac переходит в сон", "Mac проснулся"] {
            let item = try XCTUnwrap(controller.menu.items.first { $0.title == title }, title)
            XCTAssertNotNil(item.image, title)
            XCTAssertTrue(try XCTUnwrap(item.image).isTemplate, title)
            XCTAssertFalse(item.isEnabled, "An event is information, not a clickable action")
            XCTAssertNil(item.view)
        }
        model.refresh()
        controller.updateContents()
        let item = try XCTUnwrap(controller.menu.items.first { $0.title == "Запрошена локальная проверка" })
        XCTAssertNotNil(item.image)
    }

    func testEmptyHistoryHasAClockIcon() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        model.clearHistory()
        controller.updateContents()
        let visible = controller.menu.items.filter { !$0.isHidden && $0.title == "Пока нет событий" }
        XCTAssertEqual(visible.count, 1)
        XCTAssertNotNil(try XCTUnwrap(visible.first).image)
    }

    func testRouterModeDoesNotRequireLocalTunnel() async {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        model.preferences.vpnLocation = .router
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        XCTAssertTrue(controller.menu.items.contains { $0.title == "VPN: На роутере" })
        XCTAssertFalse(controller.menu.items.contains { $0.title.contains("VPN отключён") })
        XCTAssertTrue(controller.menu.items.contains { $0.title == "Защита: трафик не блокируется" })
    }

    func testNativeActionsKeepTargetsAndKeyboardShortcuts() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        let settings = try XCTUnwrap(controller.menu.items.first { $0.title == "Настройки…" })
        XCTAssertEqual(settings.keyEquivalent, ",")
        XCTAssertTrue(settings.target === controller)
        let quit = try XCTUnwrap(controller.menu.items.first { $0.title == "Выйти из Russian Armour" })
        XCTAssertEqual(quit.keyEquivalent, "q")
        let check = try XCTUnwrap(controller.menu.items.first { $0.title == "Проверить IP и страну…" })
        XCTAssertEqual(check.action, NSSelectorFromString("confirmExternalCheck"))
        XCTAssertEqual(model.externalCheck, .notChecked)
    }

    func testTrafficActionOpensWindowWithoutStartingCollection() async throws {
        _ = NSApplication.shared
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        var opened: NativeStatusMenu.WindowKind?
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { opened = $0 }
        let index = try XCTUnwrap(controller.menu.items.firstIndex { $0.title == "Сетевые соединения…" })
        controller.menu.performActionForItem(at: index)
        XCTAssertEqual(opened, .traffic)
        XCTAssertEqual(model.traffic.state, .off)
        XCTAssertFalse(model.traffic.isEnabled)
    }

    func testConsentRequiresExplicitProviderAndCancelSelectsNothing() async {
        let alert = NativeStatusMenu.externalCheckConsentAlert()
        XCTAssertEqual(alert.buttons.map(\.title), ["Через ipwho.is", "Через Country.is", "Отмена"])
        XCTAssertTrue(alert.informativeText.contains("api.country.is"))
        XCTAssertTrue(alert.informativeText.contains("ipwho.is"))
        XCTAssertEqual(NativeStatusMenu.confirmedProvider(for: .alertFirstButtonReturn), .ipWhoIS)
        XCTAssertEqual(NativeStatusMenu.confirmedProvider(for: .alertSecondButtonReturn), .countryIS)
        XCTAssertNil(NativeStatusMenu.confirmedProvider(for: .alertThirdButtonReturn))
        XCTAssertNil(NativeStatusMenu.confirmedProvider(for: .abort))
    }

    func testFailedCheckShowsActionableDetailsRatherThanStaleResult() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        var requests = 0
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in
            requests += 1
            throw URLError(.secureConnectionFailed)
        })
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        model.checkExternalIPAfterConsent()
        for _ in 0..<100 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        controller.updateContents()
        let note = try XCTUnwrap(controller.menu.items.first { $0.title == "Проверка IP не удалась — подробнее…" })
        XCTAssertTrue(note.isEnabled)
        XCTAssertTrue(note.target === controller)
        XCTAssertEqual(note.action, NSSelectorFromString("showExternalFailure"))
        XCTAssertNotNil(note.image)
        XCTAssertTrue(controller.menu.items.contains { $0.title == "IP: Ошибка проверки" })
        XCTAssertFalse(controller.menu.items.contains { $0.title.contains("Результат сброшен") })
        let alert = try XCTUnwrap(controller.externalFailureAlert())
        XCTAssertTrue(alert.informativeText.contains("Country.is"))
        XCTAssertTrue(alert.informativeText.contains("TLS"))
        XCTAssertTrue(alert.informativeText.contains("−1200"))
        XCTAssertEqual(alert.buttons.map(\.title), ["Закрыть"])
        XCTAssertEqual(requests, 1, "Opening error details must not retry the request")
    }

    func testSuccessAndInvalidationRemoveFailureActionAndShowProvider() async throws {
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let response = try EgressObservation.decode(
            Data(#"{"success":true,"ip":"203.0.113.7","country_code":"NL"}"#.utf8), provider: .ipWhoIS
        )
        var attempts = 0
        let model = AppModel(defaults: defaults, startsMonitoring: false, diagnosticsReader: { .notChecked }, egressReader: { _ in
            attempts += 1
            if attempts == 1 { throw URLError(.timedOut) }
            return response
        })
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { _ in }
        model.checkExternalIPAfterConsent(provider: .ipWhoIS)
        for _ in 0..<100 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        controller.updateContents()
        let note = try XCTUnwrap(controller.menu.items.first { $0.action == NSSelectorFromString("showExternalFailure") })
        model.checkExternalIPAfterConsent(provider: .ipWhoIS)
        controller.updateContents()
        XCTAssertEqual(note.title, "Запрос к ipwho.is…")
        XCTAssertFalse(note.isEnabled)
        XCTAssertNil(note.action)
        for _ in 0..<100 {
            if !model.externalCheck.isChecking { break }
            await Task.yield()
        }
        controller.updateContents()
        XCTAssertEqual(note.title, "ipwho.is · только запрос проверки")
        XCTAssertTrue(controller.menu.items.contains { $0.title == "IP: 203.0.113.7" })
        model.refresh()
        controller.updateContents()
        XCTAssertEqual(note.title, "Результат сброшен — повторите проверку")
        XCTAssertFalse(note.isEnabled)
        XCTAssertNil(note.action)
        XCTAssertNil(note.target)
        XCTAssertNil(note.image)
        XCTAssertNil(controller.externalFailureAlert())
    }

    func testHistoryActionOpensCorrectWindow() async throws {
        _ = NSApplication.shared
        let name = "NativeMenuTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let model = makeModel(defaults: defaults)
        var opened: NativeStatusMenu.WindowKind?
        let controller = NativeStatusMenu(model: model, createStatusItem: false) { opened = $0 }
        let index = try XCTUnwrap(controller.menu.items.firstIndex { $0.title == "Вся история…" })
        controller.menu.performActionForItem(at: index)
        XCTAssertEqual(opened, .history)
    }
}
