import Darwin
import Foundation

/// The selected provider is used for manual and automatic checks; no fallback.
public enum EgressProvider: String, CaseIterable, Codable, Equatable, Sendable {
    case countryIS
    case ipWhoIS

    public var title: String {
        switch self {
        case .countryIS: return "Country.is"
        case .ipWhoIS: return "ipwho.is"
        }
    }

    public var host: String {
        switch self {
        case .countryIS: return "api.country.is"
        case .ipWhoIS: return "ipwho.is"
        }
    }

    public var endpoint: URL {
        switch self {
        case .countryIS: return URL(string: "https://api.country.is/")!
        case .ipWhoIS: return URL(string: "https://ipwho.is/?fields=success,ip,country_code")!
        }
    }
}

public enum EgressError: Error, Equatable, LocalizedError {
    case invalidResponse
    case responseTooLarge
    case httpStatus(Int)
    case providerRejected

    public var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Сервис вернул непонятный результат. IP и страна не подтверждены."
        case .responseTooLarge: return "Ответ сервиса превышает допустимый размер."
        case .httpStatus(429): return "Сервис ограничил число запросов (HTTP 429). Попробуйте позже или выберите другой сервис."
        case .httpStatus(let status): return "Сервис вернул ошибку HTTP \(status). IP и страна не определены."
        case .providerRejected: return "Сервис не смог определить IP и страну. Можно выбрать другой сервис."
        }
    }

    /// Whitelisted text only: NSError.userInfo / localizedDescription can contain
    /// URLs, proxy details and addresses and must not reach the journal or UI.
    public static func safeMessage(for error: Error) -> String {
        if let error = error as? EgressError, let message = error.errorDescription { return message }
        let error = error as NSError
        guard error.domain == NSURLErrorDomain else {
            return "Не удалось выполнить проверку. IP и страна неизвестны."
        }
        switch URLError.Code(rawValue: error.code) {
        case .secureConnectionFailed:
            return "Не удалось установить TLS-соединение с сервисом (−1200). Можно выбрать другой сервис; проверка сертификатов остаётся включённой."
        case .serverCertificateHasBadDate, .serverCertificateUntrusted,
             .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid:
            return "macOS отклонила сертификат сервиса (\(error.code)). Проверьте дату на Mac или выберите другой сервис."
        case .clientCertificateRejected, .clientCertificateRequired:
            return "Сервис запросил или отклонил клиентский сертификат (\(error.code)). Проверка не выполнена."
        case .timedOut:
            return "Сервис не ответил вовремя (−1001). Повторите позже или выберите другой сервис."
        case .cannotFindHost, .dnsLookupFailed:
            return "Не удалось найти адрес сервиса в DNS (\(error.code)). Проверьте подключение или выберите другой сервис."
        case .notConnectedToInternet:
            return "Нет подключения к интернету (−1009). IP и страна неизвестны."
        case .cannotConnectToHost, .networkConnectionLost:
            return "Соединение с сервисом не установлено или прервано (\(error.code)). Можно повторить проверку или выбрать другой сервис."
        default:
            return "Сетевая ошибка macOS (\(error.code)). IP и страна неизвестны."
        }
    }
}

/// Observes only this app's request to the explicitly selected provider. This is
/// neither another app's route nor proof of VPN use or absence of leaks.
public struct EgressObservation: Equatable, Sendable {
    public let ip: String
    public let countryCode: String
    public let provider: EgressProvider
    public let checkedAt: Date

    public var countryName: String {
        Locale(identifier: "ru_RU").localizedString(forRegionCode: countryCode) ?? countryCode
    }

    public static func decode(
        _ data: Data,
        provider: EgressProvider = .countryIS,
        checkedAt: Date = Date()
    ) throws -> Self {
        guard data.count <= 4096 else { throw EgressError.responseTooLarge }
        let ip: String
        let country: String
        switch provider {
        case .countryIS:
            struct Response: Decodable { let ip: String; let country: String }
            guard let response = try? JSONDecoder().decode(Response.self, from: data) else {
                throw EgressError.invalidResponse
            }
            ip = response.ip
            country = response.country
        case .ipWhoIS:
            struct Response: Decodable {
                let success: Bool
                let ip: String?
                let country_code: String?
            }
            guard let response = try? JSONDecoder().decode(Response.self, from: data) else {
                throw EgressError.invalidResponse
            }
            guard response.success else { throw EgressError.providerRejected }
            guard let address = response.ip, let code = response.country_code else {
                throw EgressError.invalidResponse
            }
            ip = address
            country = code
        }
        guard country.utf8.count == 2,
              country.utf8.allSatisfy({ (65...90).contains($0) }),
              isIPLiteral(ip) else { throw EgressError.invalidResponse }
        return Self(ip: ip, countryCode: country, provider: provider, checkedAt: checkedAt)
    }

    private static func isIPLiteral(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 45,
              !value.utf8.contains(0), !value.contains("%") else { return false }
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return value.withCString { inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1 }
    }
}

public enum ExternalCheckState: Equatable, Sendable {
    case notChecked
    case checking
    case observed(EgressObservation)
    case failed(String)
    case needsRecheck(String)

    public var isChecking: Bool {
        if case .checking = self { return true }
        return false
    }
}
