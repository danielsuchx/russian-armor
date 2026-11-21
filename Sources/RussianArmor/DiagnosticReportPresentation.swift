import ArmorCore
import Foundation

extension DiagnosticReport.CheckID {
    var title: String {
        switch self {
        case .egress: return "IP и страна Russian Armor"
        case .claudeRoutes: return "Сокеты и маршруты Claude"
        case .dnsConfiguration: return "Конфигурация DNS macOS"
        case .desktopEndpoint: return "Запрос Russian Armor к claude.ai"
        case .codeEndpoint: return "Запрос Russian Armor к api.anthropic.com"
        case .watchdog: return "Наблюдатель восстановления"
        }
    }
}

extension DiagnosticReport.Status {
    var title: String {
        switch self {
        case .observed: return "Есть наблюдение"
        case .attention: return "Требует внимания"
        case .unavailable: return "Не удалось проверить"
        case .notChecked: return "Не проверено"
        case .checking: return "Проверяем…"
        case .stale: return "Результат устарел"
        case .disabled: return "Выключено"
        case .sleeping: return "Приостановлено на время сна"
        }
    }

    var symbol: String {
        switch self {
        case .observed: return "info.circle"
        case .attention: return "exclamationmark.triangle"
        case .checking: return "clock"
        case .sleeping: return "moon.zzz"
        default: return "questionmark.circle"
        }
    }
}

extension DiagnosticReport.Finding {
    var detail: String {
        switch self {
        case .armorEgressOnly: return "Есть свежий результат для запросов Russian Armor; это не проверка выхода каждого соединения Claude."
        case .noFreshEgress: return "Свежего подтверждения IP и страны нет. Старый ответ не используется."
        case .requestFailed: return "Не удалось подтвердить IP и страну. Подробности — в разделе ниже."
        case .routeSnapshotOnly: return "Источник и маршрут ОС указывают на туннель. Это не подтверждает внешний IP после VPN."
        case .noExternalSockets: return "Внешних сокетов не найдено. Это не проверка будущих соединений."
        case .downstreamUnknown: return "Снимок получен; дальнейший выход после локального узла или роутера не виден."
        case .routeOutsideTunnel: return "Обнаружен источник или маршрут вне локального туннеля. Проверьте VPN на Mac."
        case .routeUnknown: return "Не удалось получить полный снимок с определёнными маршрутами."
        case .partialSnapshot: return "Часть соединений недоступна. Неполный снимок не считается полной проверкой."
        case .configuredDNSOnly: return "Прочитаны настройки DNS. Фактический резолвер, DoH и DNS-утечки не проверены."
        case .dnsUnavailable: return "Адреса DNS в конфигурации не получены. Это не означает отсутствие DNS."
        case .endpointMatches: return "Адрес совпал с проверенным выходом Russian Armor. Маршрут самого Claude не подтверждён."
        case .endpointDiffers: return "Адрес отличается от проверенного выхода. Это повод проверить маршруты, не доказательство утечки."
        case .endpointWithoutComparison: return "Узел ответил, но свежего подтверждённого выхода для сравнения нет."
        case .endpointUnavailable: return "Узел не подтвердил адрес или действует пауза после ошибки. Это не доказательство утечки."
        case .watchdogResponding: return "Последняя проверка наблюдателя успешна. Это не сетевой kill switch."
        case .watchdogUnavailable: return "Наблюдатель восстановления недоступен. Проверьте состояние защиты."
        case .awaitingCheck: return "Результат ещё не получен."
        case .checking: return "Проверка выполняется; нового результата пока нет."
        case .expired: return "Нет свежего результата. Предыдущее наблюдение не считается актуальным."
        case .disabled: return "Проверка выключена. Результат неизвестен."
        case .sleeping: return "После пробуждения потребуется новая проверка."
        }
    }
}

enum DiagnosticReportPrivacy {
    static let contents = "В отчёте: время снимка, версия приложения, выбранное расположение VPN и состояния проверок. IP, DNS-адресов, имён профилей, путей, текстов ошибок и истории событий в нём нет."
    static let limitation = "Это сводка наблюдений, не оценка безопасности. Защита приостанавливает процессы с задержкой; отсутствие утечек и работа экспериментального firewall этим отчётом не подтверждаются."
}
