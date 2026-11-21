import Foundation

@objc public protocol ClaudeFilterProtocol {
    func updatePolicy(_ data: Data, withReply reply: @escaping (Bool) -> Void)
}

public enum ClaudeFilterIdentity {
    public static let bundle = "app.russian-armor.claude-filter"
    public static func service(team: String) -> String { team + "." + bundle }
}
