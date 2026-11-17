import Darwin
import Foundation

/// Automatic protection confirms the route with both providers. The selected
/// provider is retained as the primary/manual provider for compatible settings.
public enum EgressProvider: String, CaseIterable, Codable, Hashable, Sendable {
    case ipInfo
    case ipWhoIS
    case geoJS

    public var title: String {
        switch self {
        case .ipInfo: return "IPinfo"
        case .ipWhoIS: return "ipwho.is"
        case .geoJS: return "GeoJS"
        }
    }

    public var host: String {
        switch self {
        case .ipInfo: return "ipinfo.io"
        case .ipWhoIS: return "ipwho.is"
        case .geoJS: return "get.geojs.io"
        }
    }

    public var endpoint: URL {
        switch self {
        case .ipInfo: return URL(string: "https://ipinfo.io/json")!
        case .ipWhoIS: return URL(string: "https://ipwho.is/?fields=success,ip,country_code")!
        case .geoJS: return URL(string: "https://get.geojs.io/v1/ip/country.json")!
        }
    }

    public func lookupURL(address: String? = nil) throws -> URL {
        guard let address else { return endpoint }
        guard IPRange.isValidAddress(address) else { throw EgressError.invalidResponse }
        switch self {
        case .ipInfo: return URL(string: "https://ipinfo.io/\(address)/json")!
        case .ipWhoIS: return URL(string: "https://ipwho.is/\(address)?fields=success,ip,country_code")!
        case .geoJS: return URL(string: "https://get.geojs.io/v1/ip/country/\(address).json")!
        }
    }

    public var alternate: EgressProvider {
        self == .ipWhoIS ? .ipInfo : .ipWhoIS
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        switch value {
        case Self.ipInfo.rawValue, "countryIS": self = .ipInfo
        case Self.ipWhoIS.rawValue: self = .ipWhoIS
        case Self.geoJS.rawValue: self = .geoJS
        default:
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unknown egress provider")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum EgressError: Error, Equatable, LocalizedError {
    case invalidResponse
    case responseTooLarge
    case httpStatus(Int)
    case rateLimited(until: Date)
    case providerRejected
    case providersDisagree
    case independentConfirmationFailed

    public var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Сервис вернул непонятный результат. IP и страна не подтверждены."
        case .responseTooLarge: return "Ответ сервиса превышает допустимый размер."
        case .httpStatus(429): return "Сервис ограничил число запросов (HTTP 429). Попробуйте позже или выберите другой сервис."
        case .rateLimited: return "Сервис ограничил число запросов (HTTP 429). Повторим после указанной им паузы."
        case .httpStatus(let status): return "Сервис вернул ошибку HTTP \(status). IP и страна не определены."
        case .providerRejected: return "Сервис не смог определить IP и страну. Можно выбрать другой сервис."
        case .providersDisagree: return "Два независимых сервиса видят разный внешний IP. Выход не подтверждён."
        case .independentConfirmationFailed: return "Не удалось получить два независимых подтверждения внешнего IP."
        }
    }

    /// Whitelisted text only: NSError.userInfo / localizedDescription can contain
    /// URLs, proxy details and addresses and must not reach the journal or UI.
    public static func safeMessage(for error: Error) -> String {
        if let error = error as? EgressServiceFailure { return error.localizedDescription }
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

    public static func httpFailure(status: Int, retryAfter: String?, now: Date = Date()) -> Self {
        guard status == 429, let value = retryAfter?.trimmingCharacters(in: .whitespaces),
              !value.isEmpty, value.count <= 128 else { return .httpStatus(status) }
        if value.count <= 10, value.utf8.allSatisfy({ (48...57).contains($0) }), let seconds = Double(value) {
            return .rateLimited(until: now.addingTimeInterval(seconds))
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        if let date = formatter.date(from: value) { return .rateLimited(until: date) }
        return .httpStatus(status)
    }
}

public enum EgressConsensus {
    public static func confirm(_ first: EgressObservation, _ second: EgressObservation) throws -> EgressObservation {
        guard first.provider != second.provider else { throw EgressError.independentConfirmationFailed }
        guard first.provider == .ipWhoIS || second.provider == .ipWhoIS else {
            throw EgressError.independentConfirmationFailed
        }
        guard canonicalAddress(first.ip) == canonicalAddress(second.ip) else {
            throw EgressError.providersDisagree
        }
        // GeoIP databases regularly disagree near hosting and VPN ranges even
        // when both services observe the same address. Use the two providers to
        // confirm the egress IP, and keep one explicit source of truth for the
        // country policy so a database mismatch cannot deadlock protection.
        // ipwho.is is authoritative here: unlike IPinfo for the reported issue,
        // its country matched the network owner's RIPE-published geofeed.
        return first.provider == .ipWhoIS ? first : second
    }

    private static func canonicalAddress(_ value: String) -> Data? {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return withUnsafeBytes(of: ipv4) { Data($0) }
        }
        var ipv6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return withUnsafeBytes(of: ipv6) { Data($0) }
        }
        return nil
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
        provider: EgressProvider = .ipInfo,
        checkedAt: Date = Date()
    ) throws -> Self {
        guard data.count <= 4096 else { throw EgressError.responseTooLarge }
        let ip: String
        let country: String
        switch provider {
        case .ipInfo, .geoJS:
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
