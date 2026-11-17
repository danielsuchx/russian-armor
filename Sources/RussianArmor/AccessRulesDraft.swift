import ArmorCore
import Foundation

enum AccessEditorError: Error, LocalizedError {
    case invalidCountries, invalidIP, invalidConfiguration
    var errorDescription: String? {
        switch self {
        case .invalidCountries: return "Страны: используйте двухбуквенные коды, например NL, SE."
        case .invalidIP: return "Адреса: используйте числовой IPv4/IPv6 или CIDR, по одному на строку. Максимум 128."
        case .invalidConfiguration: return "Проверьте имена профилей, активный профиль и правила. Изменения не применены."
        }
    }
}

struct AccessRulesDraft: Equatable {
    var countries: String
    var deniedCountries: String
    var ips: String
    var deniedIPs: String

    init(_ rules: AccessRules) {
        countries = rules.allowedCountries.sorted().joined(separator: ", ")
        deniedCountries = rules.deniedCountries.sorted().joined(separator: ", ")
        ips = rules.allowedIPs.map(\.value).joined(separator: "\n")
        deniedIPs = rules.deniedIPs.map(\.value).joined(separator: "\n")
    }

    func parsed() throws -> AccessRules {
        func codes(_ text: String) throws -> Set<String> {
            let tokens = text.uppercased().split { $0.isWhitespace || $0 == "," || $0 == ";" }.map(String.init)
            guard tokens.allSatisfy({ $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } }), tokens.count <= 250 else {
                throw AccessEditorError.invalidCountries
            }
            return Set(tokens)
        }
        func ranges(_ text: String) throws -> [IPRange] {
            let tokens = text.split { $0.isWhitespace || $0 == "," || $0 == ";" }.map(String.init)
            let values = tokens.compactMap(IPRange.init)
            guard values.count == tokens.count, values.count <= 128 else { throw AccessEditorError.invalidIP }
            return values
        }
        return try AccessRules(allowedCountries: codes(countries), deniedCountries: codes(deniedCountries),
                               allowedIPs: ranges(ips), deniedIPs: ranges(deniedIPs))
    }
}
