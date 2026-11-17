import ArmorCore
import Foundation
import SystemConfiguration

/// Diagnostics are not permission. These requests use Russian Armor's ordinary
/// network stack, not Claude's sockets or the tunnel-bound admission probe.
enum ServiceProbe: String, CaseIterable, Sendable {
    case desktop, code
    var host: String { self == .desktop ? "claude.ai" : "api.anthropic.com" }
    var title: String { self == .desktop ? "Claude Desktop · claude.ai" : "Claude Code · api.anthropic.com" }
    var url: URL { URL(string: "https://\(host)/cdn-cgi/trace")! }
}

enum ServiceProbeResult: Equatable, Sendable {
    case observed(String)
    case unavailable(String)
}

struct ConnectionDiagnosticsSnapshot: Equatable, Sendable {
    let dnsServers: [String]
    let services: [ServiceProbe: ServiceProbeResult]
    let checkedAt: Date
}

struct ServiceProbeFailure: Error {
    let retryAt: Date?
}

struct ServiceProbeReader {
    static func read(_ service: ServiceProbe,
                     configuration: URLSessionConfiguration = .ephemeral) async throws -> String {
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 10
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration, delegate: ProbeSessionDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: service.url)
        request.setValue("text/plain", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.url == service.url else {
            throw EgressError.invalidResponse
        }
        guard http.statusCode == 200 else {
            let failure = EgressError.httpFailure(status: http.statusCode,
                                                  retryAfter: http.value(forHTTPHeaderField: "Retry-After"))
            if case .rateLimited(let until) = failure { throw ServiceProbeFailure(retryAt: until) }
            throw ServiceProbeFailure(retryAt: nil)
        }
        guard response.expectedContentLength <= 4096 else { throw EgressError.responseTooLarge }
        var data = Data()
        for try await byte in bytes {
            try Task.checkCancellation()
            guard data.count < 4096 else { throw EgressError.responseTooLarge }
            data.append(byte)
        }
        return try decode(data)
    }

    /// Cloudflare trace is not a documented Anthropic API. Accept only one
    /// literal address; never use trace's loc field as a GeoIP authority.
    static func decode(_ data: Data) throws -> String {
        guard data.count <= 4096 else { throw EgressError.responseTooLarge }
        guard let text = String(data: data, encoding: .utf8), !text.contains("\0") else {
            throw EgressError.invalidResponse
        }
        let addresses = text.components(separatedBy: .newlines).compactMap { line -> String? in
            guard line.hasPrefix("ip=") else { return nil }
            return String(line.dropFirst(3))
        }
        guard addresses.count == 1, let address = addresses.first, IPRange.isValidAddress(address) else {
            throw EgressError.invalidResponse
        }
        return address
    }
}

private final class ProbeSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Default OS certificate validation only. No account or client credentials.
        completionHandler(challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
                          ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }
}

enum DNSConfigurationReader {
    /// Read configured resolvers, including service-scoped entries, without a
    /// shell, DNS request, SSIDs, search domains or persistent storage.
    static func read() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "RussianArmor.DNS" as CFString, nil, nil),
              let values = SCDynamicStoreCopyMultiple(store, nil,
                ["State:/Network/Global/DNS", "State:/Network/Service/.*/DNS"] as CFArray) as? [String: [String: Any]] else { return [] }
        return addresses(in: values)
    }

    static func addresses(in values: [String: [String: Any]]) -> [String] {
        Array(Set(values.values.flatMap { $0["ServerAddresses"] as? [String] ?? [] }
            .filter { IPRange.isValidAddress($0) })).sorted()
    }
}

@MainActor
final class ConnectionDiagnosticsMonitor: ObservableObject {
    enum State: Equatable {
        case notChecked, checking, sleeping
        case observed(ConnectionDiagnosticsSnapshot)
        case stale
    }
    typealias ProbeReader = @MainActor (ServiceProbe) async throws -> String
    typealias DNSReader = @MainActor () async -> [String]
    @Published private(set) var state: State = .notChecked
    private let now: () -> Date
    private let probe: ProbeReader
    private let dns: DNSReader
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var startedAt: Date?
    private var nextCheck = Date.distantPast
    private var retryAt: [ServiceProbe: Date] = [:]
    private var servicesEnabled = false
    private var sleeping = false

    init(now: @escaping () -> Date = Date.init,
         probe: @escaping ProbeReader = { try await ServiceProbeReader.read($0) },
         dns: @escaping DNSReader = {
             await Task.detached(priority: .utility) { DNSConfigurationReader.read() }.value
         }) {
        self.now = now; self.probe = probe; self.dns = dns
    }

    deinit { task?.cancel() }

    func invalidate(sleeping: Bool = false) {
        generation = UUID()
        task?.cancel(); task = nil; startedAt = nil
        self.sleeping = sleeping
        nextCheck = .distantPast
        state = sleeping ? .sleeping : .notChecked
        // Network changes and toggles must not bypass a server's Retry-After.
    }

    func tick(online: Bool, servicesEnabled: Bool) {
        if self.servicesEnabled != servicesEnabled {
            self.servicesEnabled = servicesEnabled
            invalidate(sleeping: sleeping)
        }
        guard !sleeping else { return }
        guard online else { invalidate(); return }
        let date = now()
        if let startedAt, date < startedAt || date.timeIntervalSince(startedAt) >= 20 {
            invalidate()
            state = .stale
            nextCheck = date.addingTimeInterval(ProtectionTiming.diagnosticsInterval)
            return
        }
        if case .observed(let snapshot) = state,
           date < snapshot.checkedAt || date.timeIntervalSince(snapshot.checkedAt) >= 30 {
            state = .stale
            nextCheck = .distantPast
        }
        guard task == nil, date >= nextCheck else { return }
        let current = UUID()
        generation = current
        startedAt = date
        state = .checking
        let dns = dns, probe = probe
        task = Task { [weak self] in
            let servers = await dns()
            guard !Task.isCancelled, let self, self.generation == current else { return }
            var results: [ServiceProbe: ServiceProbeResult] = [:]
            if servicesEnabled {
                for service in ServiceProbe.allCases {
                    if let deadline = self.retryAt[service], self.now() < deadline {
                        results[service] = .unavailable("Пауза после ошибки или лимита сервиса.")
                        continue
                    }
                    do {
                        let address = try await probe(service)
                        guard !Task.isCancelled, self.generation == current else { return }
                        guard IPRange.isValidAddress(address) else { throw EgressError.invalidResponse }
                        results[service] = .observed(address)
                        self.retryAt[service] = nil
                    } catch {
                        guard !Task.isCancelled, self.generation == current else { return }
                        results[service] = .unavailable("Узел не подтвердил адрес. Это не доказательство утечки.")
                        // Undocumented endpoints may disappear or return a challenge.
                        self.retryAt[service] = max(self.now().addingTimeInterval(300),
                            (error as? ServiceProbeFailure)?.retryAt ?? .distantPast)
                    }
                }
            }
            guard !Task.isCancelled, self.generation == current else { return }
            guard self.now() >= date, self.now().timeIntervalSince(date) < 20 else {
                self.invalidate(); self.state = .stale
                self.nextCheck = self.now().addingTimeInterval(ProtectionTiming.diagnosticsInterval)
                return
            }
            self.state = .observed(ConnectionDiagnosticsSnapshot(dnsServers: servers, services: results, checkedAt: date))
            self.startedAt = nil
            self.task = nil
            self.nextCheck = max(date.addingTimeInterval(ProtectionTiming.diagnosticsInterval), self.now().addingTimeInterval(1))
        }
    }
}
