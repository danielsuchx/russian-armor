import Foundation

/// Separate cadence, request timeout and permission lifetime: a hung refresh
/// must not extend permission. Diagnostic-only use retains its slower cadence.
public enum ProtectionTiming {
    public static let checkInterval: TimeInterval = 5
    public static let confirmationLifetime: TimeInterval = 15
    public static let recoveryInterval: TimeInterval = 2
    public static let failureRetryInterval: TimeInterval = 5
    public static let diagnosticsInterval: TimeInterval = 15
}
