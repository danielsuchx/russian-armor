import ArmorCore
import Foundation

/// A compact, color-independent description of the protection status shown by
/// the menu-bar dot. The status is presentation only; it never grants access.
struct ProtectionIndicator: Equatable {
    enum State: String, Equatable {
        case green
        case yellow
        case red
        case gray
    }

    let state: State
    let title: String
    let detail: String

    static let legend = "Зелёный — защита подтверждена; жёлтый — сеть удерживается или идёт проверка; красный — защита не подтверждена или есть ошибка; серый — проверки временно приостановлены."

    static func resolve(protection: ProtectionState, packetGuardRequired: Bool,
                        firewallStatus: FirewallStatus?, now: Date = Date(), sleeping: Bool = false) -> Self {
        if sleeping {
            return Self(.gray, "Проверки приостановлены",
                        "Серый: Mac спит или проверка временно приостановлена. После пробуждения потребуется новое подтверждение.")
        }

        // A requested strict mode must be represented by its root-owned status.
        // A stale or missing status never inherits the process-level green state.
        if packetGuardRequired {
            guard let status = firewallStatus, status.isFresh(at: now) else {
                return Self(.red, "Защита не подтверждена",
                            "Красный: строгий сетевой режим запрошен, но свежего ответа root-службы нет.")
            }
            switch status.state {
            case .protected:
                return Self(.green, "Защита подтверждена",
                            "Зелёный: строгий сетевой режим подтверждён; трафик всего Mac разрешён только через проверенный VPN.")
            case .blocked:
                return Self(.yellow, "Сеть заблокирована",
                            "Жёлтый: прямой выход закрыт; VPN ещё не прошёл проверку.")
            case .recovering:
                return Self(.yellow, "Проверяем VPN",
                            "Жёлтый: прямой выход закрыт; служба восстанавливает и проверяет VPN.")
            case .disabled:
                return Self(.red, "Строгая защита выключена",
                            "Красный: строгий сетевой режим выключен, поэтому отсутствие утечки не подтверждается.")
            case .broken:
                return Self(.red, "Ошибка сетевой защиты",
                            "Красный: служба защиты сообщила об ошибке. Прямой выход должен оставаться закрыт, но требуется проверка.")
            }
        }

        switch protection {
        case .channelEnabled, .countryConfirmed:
            return Self(.green, "Защита включена",
                        "Зелёный: Claude защищён контролем процесса и подтверждённым выходом. Это не сетевой kill switch для всего Mac.")
        case .configuring, .paused:
            return Self(.yellow, protection.title,
                        "Жёлтый: Claude остаётся под ограничением, пока Russian Armor проверяет или восстанавливает защиту.")
        case .notConfigured, .setupRequired, .approvalRequired, .restartRequired, .failed:
            return Self(.red, protection.title,
                        "Красный: защита Claude не подтверждена. Запуск под защитой недоступен.")
        }
    }

    private init(_ state: State, _ title: String, _ detail: String) {
        self.state = state
        self.title = title
        self.detail = detail
    }
}
