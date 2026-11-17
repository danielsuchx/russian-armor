import Foundation

/// Safe, attributed diagnostics. Raw URLs, addresses and NSError.userInfo are never retained.
public struct EgressServiceFailure: Error, LocalizedError, Sendable {
    public let provider: EgressProvider
    public let reason: String
    public let retryAt: Date?
    fileprivate let permitsBackup: Bool
    public var errorDescription: String? { "\(provider.title): \(reason)" }
}

public struct EgressVerification: Sendable {
    public let first: EgressObservation
    public let second: EgressObservation
    public let observation: EgressObservation
}

/// Always obtains fresh observations. Backoff caches failures, never permission.
/// ipwho.is remains the country authority for the legacy single-country policy.
@MainActor
public final class EgressVerifier {
    public typealias Reader = @MainActor (EgressProvider, String?) async throws -> EgressObservation
    public static let shared = EgressVerifier()
    private let now: () -> Date
    private var failures: [EgressProvider: EgressServiceFailure] = [:]
    private var attempts: [EgressProvider: Int] = [:]

    public init(now: @escaping () -> Date = Date.init) { self.now = now }

    public func check(primary: EgressProvider, allowsBackup: Bool = true,
                      read: Reader) async throws -> EgressVerification {
        let first: EgressObservation
        do {
            first = try await query(primary, address: nil, read: read)
        } catch let failure as EgressServiceFailure where allowsBackup && primary != .ipWhoIS && failure.permitsBackup {
            // A limited selected provider cannot make the mandatory ipwho.is
            // observation disappear or turn into a one-provider permission.
            let authoritative = try await query(.ipWhoIS, address: nil, read: read)
            let backup: EgressProvider = primary == .ipInfo ? .geoJS : .ipInfo
            let independent = try await query(backup, address: authoritative.ip, read: read)
            return try verification(authoritative, independent)
        }
        let second: EgressObservation
        do {
            second = try await query(primary.alternate, address: first.ip, read: read)
        } catch let failure as EgressServiceFailure where allowsBackup && primary == .ipWhoIS && failure.permitsBackup {
            second = try await query(.geoJS, address: first.ip, read: read)
        }
        // Disagreement, malformed data and policy denials never trigger fallback.
        return try verification(first, second)
    }

    private func verification(_ first: EgressObservation, _ second: EgressObservation) throws -> EgressVerification {
        let observation = try EgressConsensus.confirm(first, second)
        return EgressVerification(first: first, second: second, observation: observation)
    }

    private func query(_ provider: EgressProvider, address: String?, read: Reader) async throws -> EgressObservation {
        try Task.checkCancellation()
        if let failure = failures[provider], let retryAt = failure.retryAt, now() < retryAt { throw failure }
        do {
            let observation = try await read(provider, address)
            try Task.checkCancellation()
            guard observation.provider == provider else { throw EgressError.invalidResponse }
            failures[provider] = nil
            attempts[provider] = nil
            return observation
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            let retryable: Bool
            let rateLimited: Bool
            var requestedRetry: Date?
            switch error {
            case EgressError.rateLimited(let until):
                retryable = true; rateLimited = true; requestedRetry = until
            case EgressError.httpStatus(let code):
                rateLimited = code == 429
                retryable = rateLimited || (500...599).contains(code)
            default:
                let failure = error as NSError
                retryable = failure.domain == NSURLErrorDomain && [
                    URLError.timedOut.rawValue, URLError.cannotFindHost.rawValue,
                    URLError.dnsLookupFailed.rawValue, URLError.cannotConnectToHost.rawValue,
                    URLError.networkConnectionLost.rawValue, URLError.notConnectedToInternet.rawValue
                ].contains(failure.code)
                rateLimited = false
            }
            var retryAt: Date?
            if retryable {
                let count = min((attempts[provider] ?? 0) + 1, 6)
                attempts[provider] = count
                let interval = min((rateLimited ? 900.0 : 10.0) * pow(2, Double(count - 1)), 21_600)
                retryAt = max(now().addingTimeInterval(1), requestedRetry ?? now().addingTimeInterval(interval))
            }
            let failure = EgressServiceFailure(provider: provider, reason: EgressError.safeMessage(for: error),
                                               retryAt: retryAt, permitsBackup: retryable)
            if retryable { failures[provider] = failure }
            throw failure
        }
    }
}
