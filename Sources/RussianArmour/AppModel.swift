import AppKit
import ArmourCore
import Combine
import Foundation

@MainActor
final class AppModel: ObservableObject {
    let protection = ProtectionState.notConfigured
    let traffic: TrafficMonitor
    @Published private(set) var network = NetworkSnapshot.checking
    @Published private(set) var diagnostics = LocalDiagnosticsSnapshot.notChecked
    @Published private(set) var externalCheck = ExternalCheckState.notChecked
    @Published private(set) var externalProvider = EgressProvider.ipWhoIS
    @Published private(set) var journal: EventJournal
    @Published var preferences: AppPreferences {
        didSet {
            save(preferences, forKey: Keys.preferences)
            let automaticSettingsChanged = oldValue.automaticIPChecks != preferences.automaticIPChecks
                || oldValue.egressProvider != preferences.egressProvider
            if automaticSettingsChanged {
                invalidateExternalCheck("Настройки проверки IP изменились.")
                externalProvider = preferences.egressProvider
                externalCheck = .notChecked
            }
            if oldValue.vpnLocation != preferences.vpnLocation {
                invalidateExternalCheck("Способ подключения изменился. Нужна новая проверка IP.")
                traffic.refresh()
            }
            if automaticSettingsChanged || oldValue.vpnLocation != preferences.vpnLocation {
                requestAutomaticExternalCheckIfNeeded()
            }
        }
    }
    @Published private(set) var storageWarning: String?
    @Published private(set) var isSleeping = false

    private enum Keys {
        static let preferences = "armour.preferences.v1"
        static let journal = "armour.journal.v1"
    }
    private let defaults: UserDefaults
    private let observer = NetworkObserver()
    private let startsMonitoring: Bool
    private let diagnosticsReader: @MainActor () -> LocalDiagnosticsSnapshot
    private var subscriptions = Set<AnyCancellable>()
    private var lastConnectivity: Connectivity?
    private var lastAvailableInterfaces: [String]?
    private var lastTunnels: TunnelObservation?
    private var externalTask: Task<Void, Never>?
    private var externalGeneration = UUID()
    private static let externalCheckInterval: TimeInterval = 60
    private var nextAutomaticCheckAt = Date.distantPast
    private let now: () -> Date
    private let automaticCheckDelay: UInt64
    private let egressReader: (EgressProvider) async throws -> EgressObservation

    init(
        defaults: UserDefaults = .standard,
        startsMonitoring: Bool = true,
        now: @escaping () -> Date = Date.init,
        automaticCheckDelay: UInt64 = 1_000_000_000,
        diagnosticsReader: @escaping @MainActor () -> LocalDiagnosticsSnapshot = { LocalDiagnosticsReader.read() },
        egressReader: @escaping (EgressProvider) async throws -> EgressObservation = { provider in try await EgressChecker(provider: provider).check() },
        trafficReader: @escaping TrafficMonitor.Reader = { try await SocketTrafficReader.snapshot() }
    ) {
        traffic = TrafficMonitor(reader: trafficReader)
        self.defaults = defaults
        self.startsMonitoring = startsMonitoring
        self.now = now
        self.automaticCheckDelay = automaticCheckDelay
        self.diagnosticsReader = diagnosticsReader
        self.egressReader = egressReader
        preferences = Self.load(AppPreferences.self, from: defaults, key: Keys.preferences)
            ?? AppPreferences()
        journal = Self.load(EventJournal.self, from: defaults, key: Keys.journal)
            ?? EventJournal()
        externalProvider = preferences.egressProvider

        observer.onUpdate = { [weak self] snapshot in self?.receive(snapshot) }
        record("Russian Armour запущен", detail: "Локальная диагностика включена. Трафик не блокируется.")
        refreshDiagnostics()
        if startsMonitoring {
            observeWorkspace()
            observer.refresh()
            Timer.publish(every: 10, on: .main, in: .common)
                .autoconnect()
                .sink { [weak self] _ in self?.refreshDiagnostics() }
                .store(in: &subscriptions)
        }
    }

    deinit { externalTask?.cancel() }

    func refresh() {
        guard !isSleeping else { return }
        invalidateExternalCheck("Запрошена новая проверка сети. Нужна новая проверка IP.")
        traffic.refresh()
        network = .checking
        record("Запрошена локальная проверка", detail: "Проверяем доступность сети, интерфейсы utun и Claude Desktop. VPN-маршрут не проверяется.")
        refreshDiagnostics()
        if startsMonitoring { observer.refresh() }
    }

    func refreshDiagnostics() {
        guard !isSleeping else { return }
        let snapshot = diagnosticsReader()
        diagnostics = snapshot
        if let previous = lastTunnels, previous != snapshot.tunnels {
            invalidateExternalCheck("Состояние интерфейсов изменилось. Нужна новая проверка IP.")
            traffic.refresh()
            if preferences.recordNetworkEvents {
                record("Состояние туннелей изменилось", detail: "\(snapshot.tunnels.title). Это не подтверждает VPN-маршрут.", kind: .network)
            }
        }
        lastTunnels = snapshot.tunnels
        expireExternalCheck()
    }

    /// Manual checks remain available even when automatic checks are disabled.
    func checkExternalIPAfterConsent(provider: EgressProvider = .countryIS) {
        beginExternalCheck(provider: provider)
    }

    func refreshExternalIP() {
        beginExternalCheck(provider: preferences.egressProvider)
    }

    private func requestAutomaticExternalCheckIfNeeded() {
        guard preferences.automaticIPChecks, !isSleeping,
              network.connectivity == .available,
              now() >= nextAutomaticCheckAt else { return }
        beginExternalCheck(provider: preferences.egressProvider, delay: automaticCheckDelay, recordsResult: false)
    }

    private func beginExternalCheck(provider: EgressProvider, delay: UInt64 = 0, recordsResult: Bool = true) {
        guard !externalCheck.isChecking, !isSleeping else { return }
        let generation = UUID()
        externalGeneration = generation
        externalProvider = provider
        externalCheck = .checking
        let read = egressReader
        externalTask = Task { [weak self] in
            do {
                if delay > 0 { try await Task.sleep(nanoseconds: delay) }
                try Task.checkCancellation()
                let observation = try await read(provider)
                guard !Task.isCancelled, let self, self.externalGeneration == generation else { return }
                guard observation.provider == provider else { throw EgressError.invalidResponse }
                self.externalCheck = .observed(observation)
                self.nextAutomaticCheckAt = self.now().addingTimeInterval(Self.externalCheckInterval)
                if recordsResult {
                    self.record("Внешний выход проверен", detail: "Только запрос Russian Armour к \(provider.title). IP и страна в историю не записываются.")
                }
                self.externalTask = nil
            } catch {
                guard !Task.isCancelled, let self, self.externalGeneration == generation else { return }
                self.externalCheck = .failed(EgressError.safeMessage(for: error))
                self.nextAutomaticCheckAt = self.now().addingTimeInterval(Self.externalCheckInterval)
                if recordsResult {
                    self.record("Не удалось проверить внешний выход", detail: "IP и страна неизвестны.", kind: .warning)
                }
                self.externalTask = nil
            }
        }
    }

    func expireExternalCheck(now date: Date? = nil) {
        if case .observed(let observation) = externalCheck,
           (date ?? now()).timeIntervalSince(observation.checkedAt) >= Self.externalCheckInterval {
            invalidateExternalCheck("Результат устарел. Нужна новая проверка IP.")
        }
        requestAutomaticExternalCheckIfNeeded()
    }

    private func invalidateExternalCheck(_ reason: String) {
        externalGeneration = UUID()
        externalTask?.cancel()
        externalTask = nil
        nextAutomaticCheckAt = .distantPast
        switch externalCheck {
        case .checking, .observed, .needsRecheck:
            externalCheck = .needsRecheck(reason)
        case .notChecked, .failed:
            break // A failure contains no observation to expire; retain its diagnostic until retry.
        }
    }

    func clearHistory() {
        journal.clear()
        save(journal, forKey: Keys.journal)
    }

    func prepareForSleep() {
        traffic.prepareForSleep()
        isSleeping = true
        invalidateExternalCheck("Mac проснулся или засыпает. Нужна новая проверка IP.")
        observer.suspend()
        network = .checking
        diagnostics = .notChecked
        record("Mac переходит в сон", detail: "Диагностика приостановлена. Сетевая защита не включена.", kind: .sleep)
    }

    func resumeAfterWake() {
        traffic.resumeAfterWake()
        isSleeping = false
        network = .checking
        record("Mac проснулся", detail: "Заново проверяем локальное состояние. Это не проверка сетевой защиты.", kind: .wake)
        refreshDiagnostics()
        if startsMonitoring { observer.refresh() }
    }

    /// Shared boundary for NWPathMonitor updates and deterministic lifecycle tests.
    func receive(_ snapshot: NetworkSnapshot) {
        guard !isSleeping else { return }
        if let previous = lastConnectivity,
           previous != snapshot.connectivity || lastAvailableInterfaces != snapshot.availableInterfaces {
            invalidateExternalCheck("Сеть изменилась. Нужна новая проверка IP.")
            traffic.refresh()
        }
        network = snapshot
        if snapshot.connectivity != lastConnectivity, preferences.recordNetworkEvents {
            record(
                snapshot.connectivity == .available ? "Сеть доступна" : "Состояние сети изменилось",
                detail: "\(snapshot.connectivity.title). Это не проверка VPN или доступа в интернет.",
                kind: snapshot.connectivity == .available ? .network : .warning
            )
        }
        lastConnectivity = snapshot.connectivity
        lastAvailableInterfaces = snapshot.availableInterfaces
        refreshDiagnostics()
    }

    private func observeWorkspace() {
        let notifications = NSWorkspace.shared.notificationCenter
        notifications.publisher(for: NSWorkspace.willSleepNotification)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.prepareForSleep() }
            .store(in: &subscriptions)
        notifications.publisher(for: NSWorkspace.didWakeNotification)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.resumeAfterWake() }
            .store(in: &subscriptions)
        for notification in [NSWorkspace.didLaunchApplicationNotification, NSWorkspace.didTerminateApplicationNotification] {
            notifications.publisher(for: notification)
                .receive(on: RunLoop.main)
                .sink { [weak self] _ in self?.refreshDiagnostics() }
                .store(in: &subscriptions)
        }
    }

    private func record(_ title: String, detail: String = "", kind: ActivityEvent.Kind = .information) {
        journal.record(ActivityEvent(kind: kind, title: title, detail: detail))
        save(journal, forKey: Keys.journal)
    }

    private func save<T: Encodable>(_ value: T, forKey key: String) {
        do {
            defaults.set(try JSONEncoder().encode(value), forKey: key)
            storageWarning = nil
        } catch {
            storageWarning = "Не удалось подготовить данные для сохранения."
        }
    }

    private static func load<T: Decodable>(_ type: T.Type, from defaults: UserDefaults, key: String) -> T? {
        guard let data = defaults.data(forKey: key), data.count <= 512 * 1024 else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }
}
