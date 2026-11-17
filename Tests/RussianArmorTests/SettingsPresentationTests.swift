import ArmorCore
import XCTest
@testable import RussianArmor

final class SettingsPresentationTests: XCTestCase {
    func testSettingsNavigationHasThreeTaskBasedSections() {
        XCTAssertEqual(SettingsSection.allCases.map(\.title), ["Защита", "Диагностика", "Основные"])
        XCTAssertEqual(Set(SettingsSection.allCases.map(\.symbol)).count, 3)
    }

    func testConfirmedCountryIsNotAnOrangeWarningOrANetworkSafetyClaim() {
        let content = SettingsProtectionContent(protection: .countryConfirmed, isSleeping: false)
        XCTAssertEqual(content.title, "Страна подтверждена")
        XCTAssertEqual(content.tone, .confirmed)
        XCTAssertTrue(content.detail.contains("на паузу"))
        XCTAssertFalse(content.detail.contains("безопасно"))
        XCTAssertFalse(content.detail.contains("блокирует"))
    }

    func testSetupPauseAndFailureKeepTheirActualReason() {
        let cases: [(ProtectionState, SettingsProtectionContent.Tone)] = [
            (.setupRequired("Нужна страна"), .attention),
            (.configuring("Подтверждение 2 из 3"), .neutral),
            (.paused("Маршрут изменился"), .attention),
            (.failed("Не удалось остановить процесс"), .failure)
        ]
        for (state, tone) in cases {
            let content = SettingsProtectionContent(protection: state, isSleeping: false)
            XCTAssertEqual(content.title, state.title)
            XCTAssertEqual(content.detail, state.detail)
            XCTAssertEqual(content.tone, tone)
        }
        XCTAssertEqual(SettingsProtectionContent(protection: .notConfigured, isSleeping: false).tone, .attention)
    }

    func testSleepDoesNotLeaveAConfirmedBadgeOrHideFailedEnforcement() {
        let sleeping = SettingsProtectionContent(protection: .countryConfirmed, isSleeping: true)
        XCTAssertEqual(sleeping.title, "Проверки приостановлены")
        XCTAssertEqual(sleeping.tone, .neutral)
        let failure = SettingsProtectionContent(protection: .failed("Сбой остановки"), isSleeping: true)
        XCTAssertEqual(failure.title, "Ошибка защиты")
        XCTAssertEqual(failure.detail, "Сбой остановки")
        XCTAssertEqual(failure.tone, .failure)
    }

    func testLegacyCountryHasTheSameSummaryAsEquivalentProfileRules() {
        let legacy = AccessConfiguration.migrating(country: "SE")
        let rules = legacy.activeProfile!.sharedRules
        XCTAssertEqual(SettingsRuleSummary.countries(rules), "Швеция · SE")
        XCTAssertNil(SettingsRuleSummary.restrictions(rules))
        XCTAssertTrue(SettingsRuleSummary.countries(.init()).contains("доступ не разрешён"))
        XCTAssertTrue(SettingsRuleSummary.country("ZZ").contains("ZZ"), "Keep the code even when macOS supplies an unknown-region label")
    }

    func testSeparateRulesKeepBothCountriesAndRestrictionCountsWithoutLiteralIPs() {
        let rules = AccessRules(allowedCountries: ["SE", "NL"], deniedCountries: ["RU"],
                                allowedIPs: [IPRange("203.0.113.0/24")!], deniedIPs: [IPRange("203.0.113.7")!])
        let countries = SettingsRuleSummary.countries(rules)
        XCTAssertTrue(countries.contains("Нидерланды · NL"))
        XCTAssertTrue(countries.contains("Швеция · SE"))
        let restrictions = SettingsRuleSummary.restrictions(rules)!
        XCTAssertTrue(restrictions.contains("Разрешённые IP/диапазоны: 1"))
        XCTAssertTrue(restrictions.contains("Запрещённые страны: 1"))
        XCTAssertTrue(restrictions.contains("Запрещённые IP/диапазоны: 1"))
        XCTAssertFalse(restrictions.contains("203.0.113"))
    }
}
