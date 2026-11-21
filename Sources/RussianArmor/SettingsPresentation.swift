import ArmorCore
import Foundation

// Presentation only: these labels never grant permission or change protection policy.
enum SettingsSection: String, CaseIterable, Identifiable {
    case protection, network, routes, audit, coverage, backup, diagnostics, guides, general

    static let navigationGroups: [(String, [Self])] = [
        ("", [.general, .protection]),
        ("Подключение", [.network, .routes, .coverage]),
        ("Инструменты", [.audit, .backup, .diagnostics, .guides])
    ]

    var id: Self { self }
    var title: String {
        switch self {
        case .protection: return "Защита"
        case .network: return "Сетевой шлюз"
        case .routes: return "Маршруты"
        case .audit: return "Проверки сети"
        case .coverage: return "Приложения"
        case .backup: return "Профили"
        case .guides: return "Помощь"
        case .diagnostics: return "Диагностика"
        case .general: return "Основные"
        }
    }
    var symbol: String {
        switch self {
        case .protection: return "shield.lefthalf.filled"
        case .network: return "network"
        case .routes: return "point.3.connected.trianglepath.dotted"
        case .audit: return "checklist"
        case .coverage: return "app.connected.to.app.below.fill"
        case .backup: return "externaldrive"
        case .guides: return "book"
        case .diagnostics: return "waveform.path.ecg"
        case .general: return "gearshape"
        }
    }
    var subtitle: String {
        switch self {
        case .protection: return "Подключение VPN и условия допуска Claude."
        case .network: return "Локальный шлюз, остановка трафика и настройки системы."
        case .routes: return "Общий выход и отдельные маршруты Claude, ChatGPT и Gemini."
        case .audit: return "14 проверок выхода, DNS и окружения для каждого сервиса."
        case .coverage: return "Настройка и подтверждение трафика приложений через шлюз."
        case .backup: return "Профили Claude Desktop, архив Claude Code и очистка сессий."
        case .guides: return "Подключение своего сервера, настройки ОС и проверка BIN."
        case .diagnostics: return "Результаты проверок, соединения и события."
        case .general: return "Запуск приложения, обновления и хранение данных."
        }
    }
}

struct SettingsProtectionContent {
    enum Tone: Equatable { case neutral, confirmed, attention, failure }
    let title: String
    let detail: String
    let symbol: String
    let tone: Tone

    init(protection: ProtectionState, isSleeping: Bool) {
        // A failed stop must remain visible even during sleep or incomplete setup.
        if case .failed = protection {
            title = protection.title
            detail = protection.detail
            symbol = "exclamationmark.octagon"
            tone = .failure
        } else if isSleeping {
            title = "Проверки приостановлены"
            detail = "После пробуждения потребуется новое подтверждение подключения."
            symbol = "moon.zzz"
            tone = .neutral
        } else {
            symbol = protection.symbol
            switch protection {
            case .countryConfirmed:
                title = "Страна подтверждена"
                detail = "При изменении сети или сбое Claude будет поставлен на паузу."
                tone = .confirmed
            case .channelEnabled:
                title = protection.title
                detail = protection.detail
                tone = .confirmed
            case .configuring:
                title = protection.title
                detail = protection.detail
                tone = .neutral
            default:
                title = protection.title
                detail = protection.detail
                tone = .attention
            }
        }
    }
}

enum SettingsRuleSummary {
    static func country(_ code: String) -> String {
        let name = Locale(identifier: "ru_RU").localizedString(forRegionCode: code) ?? code
        return name == code ? code : "\(name) · \(code)"
    }

    static func countries(_ rules: AccessRules) -> String {
        let codes = rules.allowedCountries.sorted()
        return codes.isEmpty ? "Не выбраны — доступ не разрешён" : codes.map(country).joined(separator: ", ")
    }

    static func restrictions(_ rules: AccessRules) -> String? {
        var parts: [String] = []
        if !rules.allowedIPs.isEmpty { parts.append("Разрешённые IP/диапазоны: \(rules.allowedIPs.count)") }
        if !rules.deniedCountries.isEmpty { parts.append("Запрещённые страны: \(rules.deniedCountries.count)") }
        if !rules.deniedIPs.isEmpty { parts.append("Запрещённые IP/диапазоны: \(rules.deniedIPs.count)") }
        return parts.isEmpty ? nil : parts.joined(separator: ". ")
    }
}
