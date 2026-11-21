import AppKit
import SwiftUI

@MainActor
final class ApplicationUpdater: ObservableObject {
    @Published private(set) var available: GitHubUpdate?
    @Published private(set) var busy = false
    @Published private(set) var message: String?
    private(set) var prepared: PreparedUpdate?
    private var downloadTask: Task<Void, Never>?
    private let current: ReleaseVersion?
    private let destination: URL
    private let session: URLSession
    private let ownsSession: Bool
    private let requestRestart: @MainActor () -> Void

    init(bundle: Bundle = .main, session: URLSession? = nil, requestRestart: @escaping @MainActor () -> Void = { NSApp.terminate(nil) }) {
        current = (bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String).flatMap(ReleaseVersion.init)
        destination = bundle.bundleURL
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 120
        configuration.httpShouldSetCookies = false
        ownsSession = session == nil
        self.session = session ?? URLSession(configuration: configuration, delegate: GitHubRedirects(), delegateQueue: nil)
        self.requestRestart = requestRestart
    }

    deinit { if ownsSession { session.invalidateAndCancel() } }

    func check() async {
        guard !busy else { return }
        available = nil
        guard let current else { message = "Не удалось определить версию установленного приложения."; return }
        busy = true
        defer { busy = false }
        message = "Проверяем GitHub Releases…"
        do {
            available = try await GitHubUpdate.check(after: current, session: session)
            message = available.map { "Доступна версия \($0.version)." } ?? "На GitHub нет версии новее \(current)."
        } catch {
            message = error.localizedDescription
        }
    }

    func install() {
        guard !busy, let current, let available else { return }
        busy = true
        message = "Скачиваем и проверяем версию \(available.version)…"
        downloadTask = Task {
            do {
                let next = try await UpdateInstaller.download(available, to: destination, current: current, session: session)
                if Task.isCancelled { next.discard(); return }
                prepared = next
                message = "Версия \(available.version) готова к установке."
                requestRestart()
            } catch {
                message = error.localizedDescription
                busy = false
            }
        }
    }

    func cancelDownloadForExit() async {
        downloadTask?.cancel()
        await downloadTask?.value
        discard()
    }

    func discard(error: Error? = nil) {
        prepared?.discard()
        prepared = nil
        message = error?.localizedDescription ?? available.map { "Доступна версия \($0.version)." }
        busy = false
    }
}

struct UpdateControls: View {
    @ObservedObject var updater: ApplicationUpdater

    var body: some View {
        HStack {
            Button("Проверить обновление") { Task { await updater.check() } }
                .disabled(updater.busy)
            Button("Установить обновление") { updater.install() }
                .disabled(updater.busy || updater.available == nil)
            if updater.busy { ProgressView().controlSize(.small) }
        }
        if let message = updater.message {
            Text(message).foregroundStyle(.secondary).textSelection(.enabled)
        }
    }
}
