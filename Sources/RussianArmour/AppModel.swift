import AppKit
import ArmourCore
import Combine
import Foundation

@MainActor
final class AppModel: ObservableObject {
    let processProtection: ProcessProtectionController?
    var protection: ProtectionState {
        guard let processProtection else { return .notConfigured }
        switch processProtection.status {
        case .checking(let count):
            return .configuring("Проверяем страну выхода. На паузе процессов Claude: \(count).")
        case .needsAllowedCountry(let current, let count):
            let currentText = current.map { " Сейчас определена страна \($0)." } ?? ""
            return .setupRequired("Выберите разрешённую страну VPN.\(currentText) На паузе процессов: \(count).")
        case .active:
            return .countryConfirmed
        case .paused(let reason, let count):
            return .paused("\(reason) На паузе процессов: \(count).")
        case .failed(let message):
            return .paused(message)
        }
    }
    let traffic: TrafficMonitor
    var automaticChecksEnabled: Bool { preferences.automaticIPChecks || processProtection != nil }
    var usesIndependentConfirmation: Bool { processProtection != nil }
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
            if oldValue.allowedCountryCode != preferences.allowedCountryCode {
                applyProtectionPolicy()
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
    private let routeObserver = RouteChangeObserver()
    private let startsMonitoring: Bool
    private let diagnosticsReader: @MainActor () -> LocalDiagnosticsSnapshot
    private var subscriptions = Set<AnyCancellable>()
    private var lastConnectivity: Connectivity?
    private var lastAvailableInterfaces: [String]?
    private var lastTunnels: TunnelObservation?
    private var externalTask: Task<Void, Never>?
    private var protectionObservation: EgressObservation?
    private var externalGeneration = UUID()
    private let externalCheckInterval: TimeInterval = 60
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
        trafficReader: @escaping TrafficMonitor.Reader = { try await SocketTrafficReader.snapshot() },
        processProtection: ProcessProtectionController? = nil
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
        self.processProtection = processProtection ?? (startsMonitoring ? ProcessProtectionController() : nil)
        journal = Self.load(EventJournal.self, from: defaults, key: Keys.journal)
            ?? EventJournal()
        externalProvider = preferences.egressProvider

        self.processProtection?.objectWillChange
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &subscriptions)

        observer.onUpdate = { [weak self] snapshot in self?.receive(snapshot) }
        routeObserver.onChange = { [weak self] in self?.receiveRouteChange() }
        record("Russian Armour запущен", detail: "Claude остаётся на паузе до проверки разрешённой страны выхода.")
        if preferences.allowedCountryCode == nil { self.processProtection?.requireCountry() }
        refreshDiagnostics()
        if startsMonitoring {
            observeWorkspace()
            observer.refresh()
            routeObserver.start()
            Timer.publish(every: 10, on: .main, in: .common)
                .autoconnect()
                .sink { [weak self] _ in self?.refreshDiagnostics() }
                .store(in: &subscriptions)
            Timer.publish(every: 1, on: .main, in: .common)
                .autoconnect()
                .sink { [weak self] _ in self?.expireExternalCheck() }
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
    func checkExternalIPAfterConsent(provider: EgressProvider = .ipInfo) {
        beginExternalCheck(provider: provider)
    }

    func refreshExternalIP() {
        beginExternalCheck(provider: preferences.egressProvider)
    }

    private func requestAutomaticExternalCheckIfNeeded() {
        guard automaticChecksEnabled, !isSleeping,
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
        let requiresConsensus = usesIndependentConfirmation
        externalTask = Task { [weak self] in
            do {
                if delay > 0 { try await Task.sleep(nanoseconds: delay) }
                try Task.checkCancellation()
                let observation: EgressObservation
                let policyObservation: EgressObservation
                if requiresConsensus {
                    let first: EgressObservation
                    let second: EgressObservation
                    do {
                        first = try await read(provider)
                        second = try await read(provider.alternate)
                    } catch {
                        throw EgressError.independentConfirmationFailed
                    }
                    guard first.provider == provider else { throw EgressError.invalidResponse }
                    guard second.provider == provider.alternate else { throw EgressError.invalidResponse }
                    observation = try EgressConsensus.confirm(first, second)
                    policyObservation = first.provider == .ipWhoIS ? first : second
                } else {
                    observation = try await read(provider)
                    policyObservation = observation
                }
                guard !Task.isCancelled, let self, self.externalGeneration == generation else { return }
                guard observation.provider == provider else { throw EgressError.invalidResponse }
                self.protectionObservation = policyObservation
                self.externalCheck = .observed(policyObservation)
                self.processProtection?.apply(policyObservation, allowedCountryCode: self.preferences.allowedCountryCode)
                self.nextAutomaticCheckAt = self.now().addingTimeInterval(self.externalCheckInterval)
                if recordsResult {
                    let services = requiresConsensus ? "ipwho.is и IPinfo" : provider.title
                    self.record("Внешний выход проверен", detail: "Запросы Russian Armour к \(services). IP и страна в историю не записываются.")
                }
                self.externalTask = nil
            } catch {
                guard !Task.isCancelled, let self, self.externalGeneration == generation else { return }
                self.protectionObservation = nil
                self.externalCheck = .failed(EgressError.safeMessage(for: error))
                self.processProtection?.pause("Не удалось подтвердить безопасный выход.")
                self.nextAutomaticCheckAt = self.now().addingTimeInterval(self.externalCheckInterval)
                if recordsResult {
                    self.record("Не удалось проверить внешний выход", detail: "IP и страна неизвестны.", kind: .warning)
                }
                self.externalTask = nil
            }
        }
    }

    func expireExternalCheck(now date: Date? = nil) {
        // A scheduled refresh must not suspend a healthy Claude session before
        // there is evidence that the route became unsafe. Real network/tunnel
        // changes still call invalidateExternalCheck and fail closed immediately.
        // A mismatched or failed refresh pauses protection in the task result.
        if case .observed(let observation) = externalCheck,
           (date ?? now()).timeIntervalSince(observation.checkedAt) >= externalCheckInterval,
           processProtection == nil {
            invalidateExternalCheck("Результат устарел. Нужна новая проверка IP.")
        }
        requestAutomaticExternalCheckIfNeeded()
    }

    private func invalidateExternalCheck(_ reason: String) {
        protectionObservation = nil
        processProtection?.pause(reason)
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
        processProtection?.pause("Mac переходит в сон. Ждём свежую проверку после пробуждения.")
        traffic.prepareForSleep()
        isSleeping = true
        invalidateExternalCheck("Mac проснулся или засыпает. Нужна новая проверка IP.")
        observer.suspend()
        routeObserver.stop()
        network = .checking
        diagnostics = .notChecked
        record("Mac переходит в сон", detail: "Диагностика приостановлена. Настройки системного канала сохраняются.", kind: .sleep)
    }

    func resumeAfterWake() {
        traffic.resumeAfterWake()
        isSleeping = false
        network = .checking
        record("Mac проснулся", detail: "Заново проверяем локальное состояние. Это не проверка сетевой защиты.", kind: .wake)
        refreshDiagnostics()
        if startsMonitoring {
            observer.refresh()
            routeObserver.start()
        }
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

    private func receiveRouteChange() {
        guard !isSleeping else { return }
        invalidateExternalCheck("Сетевой маршрут или адрес изменился. Нужна новая проверка IP.")
        traffic.refresh()
        refreshDiagnostics()
        observer.refresh()
        if preferences.recordNetworkEvents {
            record("Сетевой маршрут изменился", detail: "Claude остаётся на паузе до свежей проверки страны.", kind: .network)
        }
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

    func trustCurrentCountry() {
        guard let observation = currentObservation else { return }
        preferences.allowedCountryCode = observation.countryCode
        record("Разрешена страна VPN", detail: "Claude продолжит работу только после свежей проверки страны \(observation.countryCode).")
    }

    func clearAllowedCountry() {
        preferences.allowedCountryCode = nil
        processProtection?.requireCountry(currentCountryCode: currentObservation?.countryCode)
    }

    func shutdownProtection() {
        processProtection?.shutdown()
    }

    private var currentObservation: EgressObservation? {
        guard case .observed(let observation) = externalCheck else { return nil }
        return processProtection == nil ? observation : protectionObservation
    }

    private func applyProtectionPolicy() {
        guard let processProtection else { return }
        guard let allowed = preferences.allowedCountryCode else {
            processProtection.requireCountry(currentCountryCode: currentObservation?.countryCode)
            return
        }
        if let observation = currentObservation {
            processProtection.apply(observation, allowedCountryCode: allowed)
        } else {
            processProtection.pause("Ждём свежую проверку страны выхода.")
        }
    }

    private func record(_ title: String, detail: String = "", kind: ActivityEvent.Kind = .information) {
        journal.record(ActivityEvent(kind: kind, title: title, detail: detail))
        save(journal, forKey: Keys.journal)
    }

    func recordWatchdogError(_ title: String, detail: String) {
        record(title, detail: detail, kind: .warning)
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
