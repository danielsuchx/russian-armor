import AppKit
import SwiftUI

@MainActor
final class ApplicationUpdater: ObservableObject {
    @Published private(set) var available: GitHubUpdate?
    @Published private(set) var busy = false
    @Published private(set) var message: String?
    @Published private(set) var rollbackVersions: [GitHubUpdate] = []
    @Published private(set) var loadingHistory = false
    private(set) var prepared: PreparedUpdate?
    private var downloadTask: Task<Void, Never>?
    private var automaticTask: Task<Void, Never>?
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

    deinit { automaticTask?.cancel(); if ownsSession { session.invalidateAndCancel() } }

    func startAutomaticChecks(defaults: UserDefaults = .standard) {
        guard automaticTask == nil else { return }
        automaticTask = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 20_000_000_000) } catch { return }
            while !Task.isCancelled {
                if defaults.object(forKey: "armor.updates.automatic") as? Bool ?? true { await self?.check() }
                do { try await Task.sleep(nanoseconds: 3_600_000_000_000) } catch { return }
            }
        }
    }

    func loadHistory() async {
        guard !loadingHistory, let current else { return }
        loadingHistory = true
        defer { loadingHistory = false }
        do {
            rollbackVersions = try await GitHubUpdate.history(before: current, session: session)
            if rollbackVersions.isEmpty { message = "Более ранних подписанных выпусков нет." }
        } catch { message = error.localizedDescription }
    }

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
        beginInstall(available, current: current, allowRollback: false)
    }

    func installRollback(_ update: GitHubUpdate) {
        guard !busy, let current, update.version < current, rollbackVersions.contains(update) else { return }
        beginInstall(update, current: current, allowRollback: true)
    }

    private func beginInstall(_ available: GitHubUpdate, current: ReleaseVersion, allowRollback: Bool) {
        busy = true
        message = "Скачиваем и проверяем версию \(available.version)…"
        downloadTask = Task {
            do {
                let next = try await UpdateInstaller.download(available, to: destination, current: current, session: session, allowRollback: allowRollback)
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
    @AppStorage("armor.updates.automatic") private var automatic = true
    @State private var confirmRollback: GitHubUpdate?

    var body: some View {
        SettingsToggle(title: "Проверять автоматически", isOn: $automatic)
        HStack {
            Button("Проверить обновление") { Task { await updater.check() } }
                .disabled(updater.busy)
            if updater.available != nil {
                Button("Установить обновление") { updater.install() }
                    .buttonStyle(.borderedProminent).disabled(updater.busy)
            }
            if updater.busy { ProgressView().controlSize(.small) }
        }
        if let message = updater.message {
            Text(message).foregroundStyle(.secondary).textSelection(.enabled)
        }
        DisclosureGroup("Предыдущие версии") {
            VStack(alignment: .leading, spacing: 10) {
                Button(updater.loadingHistory ? "Загружаем…" : "Загрузить список") { Task { await updater.loadHistory() } }
                    .disabled(updater.loadingHistory || updater.busy)
                ForEach(updater.rollbackVersions, id: \.version.description) { release in
                    HStack {
                        Text("Russian Armor \(release.version.description)")
                        Spacer()
                        Button("Установить…") { confirmRollback = release }.disabled(updater.busy)
                    }
                }
                Text("Доступны только версии с проверяемой подписью.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(.top, 8)
        }
        .alert("Установить предыдущую версию?", isPresented: Binding(get: { confirmRollback != nil }, set: { if !$0 { confirmRollback = nil } })) {
            Button("Отмена", role: .cancel) { confirmRollback = nil }
            Button("Подготовить установку") { if let release = confirmRollback { updater.installRollback(release) }; confirmRollback = nil }
        } message: { Text("Некоторые новые настройки могут быть несовместимы с предыдущей версией. Перед заменой приложение закроет Claude и восстановит настройки шлюза.") }
    }
}
