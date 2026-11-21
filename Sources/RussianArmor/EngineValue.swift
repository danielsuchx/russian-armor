import Foundation

/// Bounded local IPC values. Raw state stays in memory and is never logged or
/// exported; screens explicitly select the fields appropriate for each task.
enum EngineValue: Codable, Equatable, Sendable {
    case object([String: EngineValue]), array([EngineValue]), string(String), number(Double), bool(Bool), null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode([EngineValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: EngineValue].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }
    subscript(_ key: String) -> EngineValue { if case .object(let v) = self { return v[key] ?? .null }; return .null }
    var string: String { if case .string(let v) = self { return v }; return "" }
    var bool: Bool { if case .bool(let v) = self { return v }; return false }
    var number: Double { if case .number(let v) = self { return v }; return 0 }
    var array: [EngineValue] { if case .array(let v) = self { return v }; return [] }
    var object: [String: EngineValue] { if case .object(let v) = self { return v }; return [:] }
    var optionalString: String? { string.isEmpty ? nil : string }
    static func optional(_ text: String?) -> EngineValue { text.map(Self.string) ?? .null }
}

enum EnginePrivacy {
    static func display(_ text: String, hideAddresses: Bool = true) -> String {
        var result = text
        // URLs may contain user names, route keys and passwords. Always remove
        // them from errors; IP hiding is an additional display preference.
        for pattern in [#"(?i)\b(?:https?|socks5?h?|zastava)://[^\s<>\"']+"#,
                        #"(?i)\b(?:token|password|api_key|secret)\s*[:=]\s*[^\s,;]+"#,
                        #"/Users/[^\s<>\"']+"#] {
            result = result.replacingOccurrences(of: pattern, with: "[скрыто]", options: .regularExpression)
        }
        if hideAddresses {
            result = result.replacingOccurrences(of: #"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])"#,
                                                 with: "[IP скрыт]", options: .regularExpression)
            result = result.replacingOccurrences(of: #"(?i)(?<![\w:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.%]*(?:/\d{1,3})?"#,
                                                 with: "[IPv6 скрыт]", options: .regularExpression)
        }
        return result
    }
}
