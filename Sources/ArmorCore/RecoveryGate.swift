import Foundation

/// Recovery evidence is local to a generation. No sleeps or I/O in the engine.
public struct RecoveryGate: Sendable {
    public let requiredSuccesses: Int
    public let minimumSpacing: TimeInterval
    public private(set) var successes = 0
    private var fingerprint: String?
    private var lastSuccess: Date?
    public var isReady: Bool { successes >= requiredSuccesses }

    public init(requiredSuccesses: Int = 3, minimumSpacing: TimeInterval = 2) {
        self.requiredSuccesses = max(1, requiredSuccesses)
        self.minimumSpacing = max(0, minimumSpacing)
    }

    public mutating func reset() {
        successes = 0
        fingerprint = nil
        lastSuccess = nil
    }

    public mutating func observe(ip: String, countries: Set<String>, at date: Date) {
        let next = ip + "|" + countries.sorted().joined(separator: ",")
        if fingerprint != next || lastSuccess.map({ date < $0 }) == true {
            reset()
            fingerprint = next
        }
        guard lastSuccess.map({ date.timeIntervalSince($0) >= minimumSpacing }) ?? true else { return }
        successes = min(requiredSuccesses, successes + 1)
        lastSuccess = date
    }
}
