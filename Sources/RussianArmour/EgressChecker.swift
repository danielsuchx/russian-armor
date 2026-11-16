import ArmourCore
import Foundation

/// No cookies, persisted cache, background requests or automatic redirects.
/// Invoked by the enabled automatic policy or an explicitly requested manual check.
struct EgressChecker {
    private let provider: EgressProvider
    private let session: URLSession

    init(provider: EgressProvider = .ipInfo, configuration: URLSessionConfiguration = .ephemeral) {
        self.provider = provider
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 12
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
    }

    func check() async throws -> EgressObservation {
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: provider.endpoint)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else { throw EgressError.invalidResponse }
        guard http.statusCode == 200 else { throw EgressError.httpStatus(http.statusCode) }
        guard response.expectedContentLength <= 4096 else { throw EgressError.responseTooLarge }
        var body = Data()
        for try await byte in bytes {
            try Task.checkCancellation()
            guard body.count < 4096 else { throw EgressError.responseTooLarge }
            body.append(byte)
        }
        return try EgressObservation.decode(body, provider: provider)
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
