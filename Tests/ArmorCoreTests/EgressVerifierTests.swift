import Foundation
import XCTest
@testable import ArmorCore

@MainActor
final class EgressVerifierTests: XCTestCase {
    private func observation(_ provider: EgressProvider, ip: String = "203.0.113.7", country: String = "NL") throws -> EgressObservation {
        let body: [String: Any] = provider == .ipWhoIS
            ? ["success": true, "ip": ip, "country_code": country]
            : ["ip": ip, "country": country]
        return try .decode(JSONSerialization.data(withJSONObject: body), provider: provider)
    }

    func testRateLimitUsesBackupForSameFreshIPAndHonorsRetryAfter() async throws {
        var date = Date(timeIntervalSince1970: 1_000)
        let deadline = date.addingTimeInterval(7_200)
        var ip = "203.0.113.7"
        let verifier = EgressVerifier(now: { date })
        var requests: [(EgressProvider, String?)] = []
        let read: EgressVerifier.Reader = { provider, address in
            requests.append((provider, address))
            if provider == .ipInfo, date < deadline { throw EgressError.rateLimited(until: deadline) }
            return try self.observation(provider, ip: address ?? ip)
        }
        let initial = try await verifier.check(primary: .ipWhoIS, read: read)
        XCTAssertEqual(initial.second.provider, .geoJS)
        XCTAssertEqual(requests.map(\.0), [.ipWhoIS, .ipInfo, .geoJS])
        XCTAssertEqual(requests.last?.1, ip)

        date += 45
        ip = "203.0.113.8"
        let changed = try await verifier.check(primary: .ipWhoIS, read: read)
        XCTAssertEqual(changed.observation.ip, ip, "A cooldown must never reuse a cached egress permission")
        XCTAssertEqual(requests.map(\.0), [.ipWhoIS, .ipInfo, .geoJS, .ipWhoIS, .geoJS])
        XCTAssertEqual(requests.last?.1, ip, "The backup database must look up the new primary IP")

        date = deadline
        let restored = try await verifier.check(primary: .ipWhoIS, read: read)
        XCTAssertEqual(restored.second.provider, .ipInfo)
        XCTAssertEqual(Array(requests.suffix(2)).map(\.0), [.ipWhoIS, .ipInfo])
    }

    func testRepeatedManualChecksAndProviderSelectionCannotBypassCooldown() async throws {
        var date = Date(timeIntervalSince1970: 1_000)
        let verifier = EgressVerifier(now: { date })
        var infoRequests = 0
        let read: EgressVerifier.Reader = { provider, _ in
            if provider == .ipInfo { infoRequests += 1; throw EgressError.httpStatus(429) }
            return try self.observation(provider)
        }
        _ = try await verifier.check(primary: .ipWhoIS, read: read)
        for _ in 0..<10 {
            date += 1
            _ = try await verifier.check(primary: .ipInfo, read: read)
        }
        XCTAssertEqual(infoRequests, 1)
        date = Date(timeIntervalSince1970: 1_900)
        _ = try await verifier.check(primary: .ipWhoIS, read: read)
        XCTAssertEqual(infoRequests, 2)
        date = Date(timeIntervalSince1970: 2_800)
        _ = try await verifier.check(primary: .ipWhoIS, read: read)
        XCTAssertEqual(infoRequests, 2, "A repeated limit extends the cooldown exponentially")
    }

    func testTLSMalformedDataAndDisagreementNeverTriggerFallback() async throws {
        for error: Error in [URLError(.secureConnectionFailed), EgressError.invalidResponse, EgressError.responseTooLarge] {
            let verifier = EgressVerifier()
            var requests: [EgressProvider] = []
            do {
                _ = try await verifier.check(primary: .ipWhoIS) { provider, _ in
                    requests.append(provider)
                    if provider == .ipInfo { throw error }
                    return try self.observation(provider)
                }
                XCTFail("An untrusted response was accepted")
            } catch { }
            XCTAssertEqual(requests, [.ipWhoIS, .ipInfo])
        }
        var requests: [EgressProvider] = []
        do {
            _ = try await EgressVerifier().check(primary: .ipWhoIS) { provider, _ in
                requests.append(provider)
                return try self.observation(provider, ip: provider == .ipInfo ? "203.0.113.8" : "203.0.113.7")
            }
            XCTFail("Different IPs were accepted")
        } catch { XCTAssertEqual(error as? EgressError, .providersDisagree) }
        XCTAssertEqual(requests, [.ipWhoIS, .ipInfo])
    }

    func testUnavailableBackupAndExplicitProbeAllowlistFailClosed() async throws {
        for allowsBackup in [false, true] {
            var requests: [EgressProvider] = []
            do {
                _ = try await EgressVerifier().check(primary: .ipWhoIS, allowsBackup: allowsBackup) { provider, _ in
                    requests.append(provider)
                    if provider == .ipInfo { throw EgressError.httpStatus(429) }
                    if provider == .geoJS { throw EgressError.httpStatus(503) }
                    return try self.observation(provider)
                }
                XCTFail("A single source must never grant permission")
            } catch let failure as EgressServiceFailure {
                XCTAssertEqual(failure.provider, allowsBackup ? .geoJS : .ipInfo)
                XCTAssertNotNil(failure.retryAt)
            }
            XCTAssertEqual(requests, allowsBackup ? [.ipWhoIS, .ipInfo, .geoJS] : [.ipWhoIS, .ipInfo])
        }
    }

    func testCancellationDoesNotTryBackupOrCacheFailure() async throws {
        let verifier = EgressVerifier()
        var requests: [EgressProvider] = []
        do {
            _ = try await verifier.check(primary: .ipWhoIS) { provider, _ in
                requests.append(provider)
                if provider == .ipInfo { throw CancellationError() }
                return try self.observation(provider)
            }
            XCTFail("Cancelled verification was accepted")
        } catch is CancellationError { }
        let restored = try await verifier.check(primary: .ipWhoIS) { provider, _ in
            requests.append(provider)
            return try self.observation(provider)
        }
        XCTAssertEqual(restored.second.provider, .ipInfo)
        XCTAssertEqual(requests, [.ipWhoIS, .ipInfo, .ipWhoIS, .ipInfo])
    }

    func testSafeFailureDoesNotExposeRawURLOrProxyDetails() async throws {
        let secret = "https://user:password@proxy.example/private"
        do {
            _ = try await EgressVerifier().check(primary: .ipWhoIS) { _, _ in
                throw NSError(domain: NSURLErrorDomain, code: URLError.secureConnectionFailed.rawValue,
                              userInfo: [NSLocalizedDescriptionKey: secret, NSURLErrorFailingURLStringErrorKey: secret])
            }
            XCTFail("TLS failure was accepted")
        } catch {
            let message = EgressError.safeMessage(for: error)
            XCTAssertTrue(message.contains("ipwho.is"))
            XCTAssertTrue(message.contains("TLS"))
            XCTAssertFalse(message.contains("password"))
            XCTAssertFalse(message.contains("proxy.example"))
        }
    }
}
