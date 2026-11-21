import ArmorTunnel
import AppKit
import ArmorCore
import Combine
import Foundation
import ServiceManagement

enum ClaudeSafeLaunchError: Error, Equatable, LocalizedError {
    case notInstalled
    case alreadyRunning
    case protectionUnavailable
    case protectionChanged
    case launchFailed

    var errorDescription: String? {
        switch self {
        case .notInstalled: return "Claude Desktop не найден на этом Mac."
        case .alreadyRunning: return "Claude Desktop уже запущен."
        case .protectionUnavailable: return "Запуск доступен только после свежего подтверждения разрешённой страны."
        case .protectionChanged: return "Состояние сети изменилось во время запуска. Claude поставлен на паузу."
        case .launchFailed: return "macOS не удалось запустить Claude Desktop."
        }
    }
}

@MainActor
private enum ClaudeDesktopLauncher {
    static func launch() async throws {
        guard let url = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: LocalDiagnosticsReader.claudeBundleIdentifier
        ) else { throw ClaudeSafeLaunchError.notInstalled }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.addsToRecentItems = true
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    let updater = ApplicationUpdater()
    let tunnelReaderRegistration = TunnelReaderRegistration()

    struct CountryComparison: Equatable {
        let ipWhoIS: String
        let independentCountry: String
        let independentProvider: EgressProvider

        init(first: EgressObservation, second: EgressObservation) {
            let authoritative = first.provider == .ipWhoIS ? first : second
            let independent = first.provider == .ipWhoIS ? second : first
            ipWhoIS = authoritative.countryCode
            independentCountry = independent.countryCode
            independentProvider = independent.provider
        }

        var agrees: Bool { ipWhoIS == independentCountry }
        var countries: Set<String> { [ipWhoIS, independentCountry] }
        var services: String { "ipwho.is + \(independentProvider.title)" }
        var detail: String { "ipwho.is \(ipWhoIS), \(independentProvider.title) \(independentCountry)" }
    }

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
            return .failed(message)
        }
    }
    let traffic: TrafficMonitor
    let happConnections: HappConnectionMonitor
    let claudeRoutes: ClaudeRouteMonitor
    let connectionDiagnostics: ConnectionDiagnosticsMonitor
    private let runsConnectionDiagnostics: Bool
    private let requiresClaudeRoutes: Bool
    private let requiresTunnelChecks: Bool
    private let tunnelEgressReader: (String?) async throws -> TunnelCheckResult
    private let egressVerifier: EgressVerifier
    private var recovery: RecoveryGate
    var recoveryProgress: String { "\(recovery.successes) из \(recovery.requiredSuccesses) успешных проверок" }
    var accessConfiguration: AccessConfiguration {
        preferences.accessConfiguration ?? .migrating(country: preferences.allowedCountryCode)
    }
    var needsRuleSetup: Bool {
        if preferences.accessConfiguration == nil { return preferences.allowedCountryCode == nil }
        guard accessConfiguration.isValid, let profile = accessConfiguration.activeProfile else { return true }
        return ProtectedApplication.allCases.allSatisfy { profile.rules(for: $0).allowedCountries.isEmpty }
    }
    func accessDecision(for application: ProtectedApplication) -> AccessDecision {
        guard accessConfiguration.isValid, let profile = accessConfiguration.activeProfile else {
            return AccessRules().evaluate(ip: nil, countries: [])
        }
        let observation = currentObservation
        let countries: Set<String>
        if preferences.accessConfiguration != nil, !protectionCountries.isEmpty {
            countries = protectionCountries
        } else {
            countries = Set(observation.map { [$0.countryCode] } ?? [])
        }
        return profile.rules(for: application).evaluate(ip: observation?.ip, countries: countries)
    }
    var automaticChecksEnabled: Bool { preferences.automaticIPChecks || processProtection != nil }
    var usesIndependentConfirmation: Bool { processProtection != nil }
    var externalRetryAt: Date? {
        guard automaticChecksEnabled, case .failed = externalCheck,
              nextAutomaticCheckAt != .distantPast else { return nil }
        return nextAutomaticCheckAt
    }
    @Published private(set) var network = NetworkSnapshot.checking
    @Published private(set) var diagnostics = LocalDiagnosticsSnapshot.notChecked
    @Published private(set) var externalCheck = ExternalCheckState.notChecked
    @Published private(set) var externalProvider = EgressProvider.ipWhoIS
    @Published private(set) var countryComparison: CountryComparison?
    @Published private(set) var journal: EventJournal
    @Published private(set) var watchdogHealthy = true
    @Published private(set) var claudeLaunchInProgress = false
    @Published private(set) var verifiedTunnel: VerifiedTunnel?
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
            if oldValue.vpnLocation != preferences.vpnLocation || oldValue.preferredTunnelOwner != preferences.preferredTunnelOwner {
                invalidateExternalCheck("Способ подключения изменился. Нужна новая проверка IP.")
                traffic.refresh()
                claudeRoutes.refresh()
            }
            if oldValue.accessConfiguration != preferences.accessConfiguration {
                invalidateExternalCheck("Правила допуска изменились. Нужна свежая проверка.")
                requestAutomaticExternalCheckIfNeeded()
            }
            if oldValue.allowedCountryCode != preferences.allowedCountryCode {
                applyProtectionPolicy()
            }
            if oldValue.recordNetworkEvents != preferences.recordNetworkEvents {
                happConnections.receive(traffic.state, recordsEvents: preferences.recordNetworkEvents)
            }
            if oldValue.serviceDiagnosticsEnabled != preferences.serviceDiagnosticsEnabled {
                connectionDiagnostics.invalidate(sleeping: isSleeping)
                refreshConnectionDiagnostics()
            }
            if oldValue.startAtLogin != preferences.startAtLogin {
                updateAutostart(preferences.startAtLogin)
            }
            if automaticSettingsChanged || oldValue.vpnLocation != preferences.vpnLocation || oldValue.preferredTunnelOwner != preferences.preferredTunnelOwner {
                requestAutomaticExternalCheckIfNeeded()
            }
        }
    }
    @Published private(set) var storageWarning: String?
    @Published private(set) var isSleeping = false

    private enum Keys {
        static let preferences = "armor.preferences.v1"
        static let journal = "armor.journal.v1"
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
    private var protectionCountries = Set<String>()
    private var confirmedAt: Date?
    private var externalCheckStartedAt: Date?
    private let externalCheckTimeout: TimeInterval = 25
    private var externalGeneration = UUID()
    private let externalCheckInterval: TimeInterval = 60
    private var confirmationLifetime: TimeInterval {
        usesIndependentConfirmation ? ProtectionTiming.confirmationLifetime : externalCheckInterval
    }
    private var failureRetryInterval: TimeInterval {
        usesIndependentConfirmation ? ProtectionTiming.failureRetryInterval : externalCheckInterval
    }
    private var nextAutomaticCheckAt = Date.distantPast
    private let now: () -> Date
    private let automaticCheckDelay: UInt64
    private let egressReader: (EgressProvider) async throws -> EgressObservation
    private let claudeLauncher: () async throws -> Void

    init(
        defaults: UserDefaults = .standard,
        startsMonitoring: Bool = true,
        now: @escaping () -> Date = Date.init,
        automaticCheckDelay: UInt64 = 1_000_000_000,
        diagnosticsReader: @escaping @MainActor () -> LocalDiagnosticsSnapshot = { LocalDiagnosticsReader.read() },
        egressReader: @escaping (EgressProvider) async throws -> EgressObservation = { provider in try await EgressChecker(provider: provider).check() },
        trafficReader: @escaping TrafficMonitor.Reader = { try await SocketTrafficReader.snapshot() },
        processProtection: ProcessProtectionController? = nil,
        claudeRouteReader: ClaudeRouteMonitor.Reader? = nil,
        recoverySuccesses: Int? = nil,
        tunnelEgressReader: ((String?) async throws -> TunnelCheckResult)? = nil,
        happConnectionMonitor: HappConnectionMonitor? = nil,
        connectionDiagnostics: ConnectionDiagnosticsMonitor? = nil,
        claudeLauncher: @escaping () async throws -> Void = { try await ClaudeDesktopLauncher.launch() }
    ) {
        self.connectionDiagnostics = connectionDiagnostics ?? ConnectionDiagnosticsMonitor(now: now)
        self.runsConnectionDiagnostics = startsMonitoring || connectionDiagnostics != nil
        traffic = TrafficMonitor(reader: trafficReader)
        self.happConnections = happConnectionMonitor ?? HappConnectionMonitor()
        self.defaults = defaults
        self.startsMonitoring = startsMonitoring
        self.requiresTunnelChecks = startsMonitoring || tunnelEgressReader != nil
        let verifier = EgressVerifier(now: now)
        self.egressVerifier = verifier
        self.tunnelEgressReader = tunnelEgressReader ?? { try await TunnelEgressChecker.check(ownerKey: $0, verifier: verifier, independentExit: true) }
        recovery = RecoveryGate(requiredSuccesses: recoverySuccesses ?? (startsMonitoring ? 3 : 1))
        self.now = now
        self.automaticCheckDelay = automaticCheckDelay
        self.diagnosticsReader = diagnosticsReader
        self.egressReader = egressReader
        self.claudeLauncher = claudeLauncher
        preferences = Self.load(AppPreferences.self, from: defaults, key: Keys.preferences)
            ?? AppPreferences()
        if let processProtection {
            self.processProtection = processProtection
        } else if startsMonitoring {
            let ledger = SuspensionLedger()
            self.processProtection = ProcessProtectionController(
                loadSuspended: { try ledger.load() },
                saveSuspended: { try ledger.save($0) }
            )
        } else {
            self.processProtection = nil
        }
        requiresClaudeRoutes = startsMonitoring || claudeRouteReader != nil
        let controller = self.processProtection
        claudeRoutes = ClaudeRouteMonitor(
            now: now,
            identities: { [weak controller] in controller?.monitoredProcessIdentities() ?? [] },
            reader: claudeRouteReader ?? { try await ClaudeSocketRouteReader.snapshot(identities: $0) }
        )
        journal = Self.load(EventJournal.self, from: defaults, key: Keys.journal)
            ?? EventJournal()
        externalProvider = preferences.egressProvider

        happConnections.onMultipleAddresses = { [weak self] count in
            guard let self, self.preferences.recordNetworkEvents, self.traffic.isEnabled, !self.isSleeping else { return }
            self.record("У Happ несколько внешних адресов",
                        detail: "В двух последовательных снимках сокетов подписанного туннеля Happ обнаружено несколько внешних IP (в последнем — \(count)). Это могут быть VPN-серверы, DNS или служебные узлы; число VPN-серверов и передачу трафика снимок не подтверждает. Адреса не сохранены.",
                        kind: .network)
        }
        traffic.$state
            .sink { [weak self] state in
                guard let self else { return }
                self.happConnections.receive(state, recordsEvents: self.preferences.recordNetworkEvents)
            }
            .store(in: &subscriptions)

        self.processProtection?.objectWillChange
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &subscriptions)

        claudeRoutes.onChange = { [weak self] in
            guard let self else { return }
            self.objectWillChange.send()
            let routeProblem: Bool
            switch self.claudeRoutes.state {
            case .failed, .sleeping: routeProblem = true
            case .checking: routeProblem = false
            case .observed(let snapshot): routeProblem = snapshot.pauseReason(vpnLocation: self.preferences.vpnLocation) != nil
            case .off: routeProblem = false
            }
            if routeProblem, self.recovery.successes > 0 {
                self.recovery.reset()
                self.nextAutomaticCheckAt = .distantPast
            }
            self.applyProtectionPolicy()
            if !self.recovery.isReady { self.requestAutomaticExternalCheckIfNeeded() }
        }
        if requiresClaudeRoutes, self.processProtection != nil { claudeRoutes.start() }
        observer.onUpdate = { [weak self] snapshot in self?.receive(snapshot) }
        routeObserver.onChange = { [weak self] in self?.receiveRouteChange() }
        record("Russian Armor запущен", detail: "Claude остаётся на паузе до проверки разрешённой страны выхода.")
        if needsRuleSetup { self.processProtection?.requireCountry() }
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
        claudeRoutes.refresh()
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
        if currentObservation == nil { countryComparison = nil }
        externalCheck = .checking
        externalCheckStartedAt = now()
        let startedAt = now()
        let read = egressReader
        let requiresConsensus = usesIndependentConfirmation
        let boundToTunnel = requiresTunnelChecks && preferences.vpnLocation == .thisMac
        let tunnelRead = tunnelEgressReader
        let ownerKey = preferences.preferredTunnelOwner
        let verifier = egressVerifier
        externalTask = Task { [weak self] in
            do {
                if delay > 0 { try await Task.sleep(nanoseconds: delay) }
                try Task.checkCancellation()
                let observation: EgressObservation
                let policyObservation: EgressObservation
                let comparison: CountryComparison?
                var checkedTunnel: VerifiedTunnel?
                if boundToTunnel {
                    let result = try await tunnelRead(ownerKey)
                    observation = try EgressConsensus.confirm(result.first, result.second)
                    policyObservation = observation
                    comparison = CountryComparison(first: result.first, second: result.second)
                    checkedTunnel = result.tunnel
                } else if requiresConsensus {
                    let result = try await verifier.check(primary: provider, mode: .independentExit) { source, _ in
                        return try await read(source)
                    }
                    observation = result.observation
                    comparison = CountryComparison(first: result.first, second: result.second)
                    policyObservation = observation
                } else {
                    observation = try await read(provider)
                    policyObservation = observation
                    comparison = nil
                }
                guard !Task.isCancelled, let self, self.externalGeneration == generation else { return }
                if !requiresConsensus {
                    guard observation.provider == provider else { throw EgressError.invalidResponse }
                }
                guard self.now().timeIntervalSince(startedAt) < self.externalCheckTimeout else {
                    throw URLError(.timedOut)
                }
                if self.verifiedTunnel != checkedTunnel {
                    self.recovery.reset()
                }
                if self.protectionObservation?.ip != policyObservation.ip {
                    self.connectionDiagnostics.invalidate()
                }
                self.verifiedTunnel = checkedTunnel
                self.countryComparison = comparison
                self.confirmedAt = startedAt
                self.externalCheckStartedAt = nil
                self.protectionObservation = policyObservation
                self.protectionCountries = comparison?.countries ?? [observation.countryCode]
                self.externalCheck = .observed(policyObservation)
                self.recovery.observe(ip: observation.ip, countries: self.protectionCountries, at: startedAt)
                self.applyProtectionPolicy()
                // Recovery is deliberately slower than suspension, without a grace
                // period that would keep working after a failed verification.
                let interval = !self.recovery.isReady ? ProtectionTiming.recoveryInterval
                    : (requiresConsensus ? ProtectionTiming.checkInterval : self.externalCheckInterval)
                // Do not catch up missed ticks with a burst after a slow response.
                self.nextAutomaticCheckAt = max(startedAt.addingTimeInterval(interval), self.now().addingTimeInterval(1))
                if recordsResult {
                    let services = comparison?.services ?? provider.title
                    self.record("Внешний выход проверен", detail: "Запросы Russian Armor к \(services). IP и страна в историю не записываются.")
                }
                self.externalTask = nil
            } catch {
                guard !Task.isCancelled, let self, self.externalGeneration == generation else { return }
                self.recovery.reset()
                self.protectionObservation = nil
                self.confirmedAt = nil
                self.externalCheckStartedAt = nil
                self.countryComparison = nil
                self.verifiedTunnel = nil
                self.externalCheck = .failed((error as? TunnelCheckError)?.errorDescription ?? EgressError.safeMessage(for: error))
                self.processProtection?.pause("Не удалось подтвердить безопасный выход.")
                self.nextAutomaticCheckAt = self.now().addingTimeInterval(self.failureRetryInterval)
                if let retryAt = (error as? EgressServiceFailure)?.retryAt {
                    self.nextAutomaticCheckAt = max(self.nextAutomaticCheckAt, retryAt)
                }
                if recordsResult {
                    self.record("Не удалось проверить внешний выход", detail: "IP и страна неизвестны.", kind: .warning)
                }
                self.externalTask = nil
            }
        }
    }

    private func refreshConnectionDiagnostics() {
        guard runsConnectionDiagnostics, !isSleeping else { return }
        connectionDiagnostics.tick(online: network.connectivity == .available,
                                   servicesEnabled: preferences.serviceDiagnosticsEnabled)
    }

    func expireExternalCheck(now date: Date? = nil) {
        refreshConnectionDiagnostics()
        claudeRoutes.expire()
        let instant = date ?? now()
        if let confirmedAt, instant < confirmedAt {
            invalidateExternalCheck("Системное время изменилось. Нужна свежая проверка страны.")
        }
        if let started = externalCheckStartedAt,
           instant.timeIntervalSince(started) >= externalCheckTimeout {
            invalidateExternalCheck("Сервисы не ответили вовремя. Claude остаётся на паузе.")
            externalCheck = .failed(EgressError.safeMessage(for: URLError(.timedOut)))
            nextAutomaticCheckAt = instant.addingTimeInterval(failureRetryInterval)
            return
        }
        if let confirmedAt, instant.timeIntervalSince(confirmedAt) >= confirmationLifetime {
            // Revoke the lease even while a refresh is in flight. A hung request
            // must never turn a previous success into an unlimited permission.
            self.confirmedAt = nil
            recovery.reset()
            protectionObservation = nil
            processProtection?.pause("Подтверждение страны устарело. Ждём свежую проверку.")
            if !externalCheck.isChecking {
                externalCheck = .needsRecheck("Подтверждение страны устарело.")
            }
        } else if processProtection == nil,
                  case .observed(let observation) = externalCheck,
                  instant.timeIntervalSince(observation.checkedAt) >= externalCheckInterval {
            invalidateExternalCheck("Результат устарел. Нужна новая проверка IP.")
        }
        requestAutomaticExternalCheckIfNeeded()
    }

    private func invalidateExternalCheck(_ reason: String) {
        connectionDiagnostics.invalidate(sleeping: isSleeping)
        recovery.reset()
        verifiedTunnel = nil
        protectionCountries = []
        protectionObservation = nil
        confirmedAt = nil
        externalCheckStartedAt = nil
        countryComparison = nil
        processProtection?.pause(reason)
        claudeRoutes.refresh()
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

    var recentEventsTitle: String {
        journal.unreadCount == 0 ? "Последние события" : "Последние события · новых: \(journal.unreadCount)"
    }

    func markHistoryRead() {
        guard journal.unreadCount > 0 else { return }
        journal.markAllRead()
        save(journal, forKey: Keys.journal)
    }

    func clearHistory() {
        journal.clear()
        save(journal, forKey: Keys.journal)
    }

    func prepareForSleep() {
        processProtection?.pause("Mac переходит в сон. Ждём свежую проверку после пробуждения.")
        traffic.prepareForSleep()
        claudeRoutes.prepareForSleep()
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
        connectionDiagnostics.invalidate()
        claudeRoutes.resumeAfterWake()
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
        if snapshot.connectivity != .available {
            invalidateExternalCheck("Сеть недоступна. Claude остаётся на паузе.")
        } else if let previous = lastConnectivity,
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

    func saveAccessConfiguration(_ configuration: AccessConfiguration) throws {
        guard configuration.isValid, try JSONEncoder().encode(configuration).count <= 400 * 1024 else { throw AccessEditorError.invalidConfiguration }
        preferences.accessConfiguration = configuration
        record("Правила допуска сохранены", detail: "Запреты имеют приоритет. Адреса и названия профилей не записываются в историю.")
    }

    func trustCurrentCountry() {
        guard let observation = currentObservation else { return }
        if preferences.accessConfiguration != nil {
            var configuration = accessConfiguration
            guard let index = configuration.profiles.firstIndex(where: { $0.id == configuration.activeProfileID }) else { return }
            // This action is only for first-run setup. It must not replace an
            // existing deny or broaden separately configured application rules.
            guard needsRuleSetup else { return }
            configuration.profiles[index].sharedRules.allowedCountries.insert(observation.countryCode)
            configuration.profiles[index].desktopRules.allowedCountries.insert(observation.countryCode)
            configuration.profiles[index].codeRules.allowedCountries.insert(observation.countryCode)
            try? saveAccessConfiguration(configuration)
        } else {
            preferences.allowedCountryCode = observation.countryCode
        }
        record("Разрешена страна VPN", detail: "Claude продолжит работу только после свежей проверки страны \(observation.countryCode).")
    }

    func clearAllowedCountry() {
        preferences.allowedCountryCode = nil
        processProtection?.requireCountry(currentCountryCode: currentObservation?.countryCode)
    }

    func shutdownProtection() {
        processProtection?.shutdown()
    }

    func closeClaudeBeforeApplicationExit() async throws {
        guard let processProtection else { return }
        do {
            try await processProtection.terminateProtectedProcesses()
            record("Claude закрыт перед выходом", detail: "Russian Armor завершает работу только после закрытия распознанных процессов Claude.")
        } catch {
            record("Выход отменён", detail: "Не удалось закрыть все процессы Claude. Защита продолжает работать.", kind: .warning)
            throw error
        }
    }

    var canLaunchClaudeUnderProtection: Bool {
        guard !claudeLaunchInProgress, !isSleeping, watchdogHealthy,
              network.connectivity == .available,
              diagnostics.claudeDesktop == .notRunning,
              desktopPolicyAllowsLaunch,
              !requiresClaudeRoutes || claudeRoutes.pauseReason(vpnLocation: preferences.vpnLocation) == nil,
              !startsMonitoring || routeObserver.isMonitoring else { return false }
        return true
    }

    func launchClaudeUnderProtection() async throws {
        refreshDiagnostics()
        if diagnostics.claudeDesktop == .notInstalled { throw ClaudeSafeLaunchError.notInstalled }
        if diagnostics.claudeDesktop == .running { throw ClaudeSafeLaunchError.alreadyRunning }
        guard canLaunchClaudeUnderProtection else { throw ClaudeSafeLaunchError.protectionUnavailable }

        let launchGeneration = externalGeneration
        let launchConfirmation = confirmedAt
        claudeLaunchInProgress = true
        defer { claudeLaunchInProgress = false }
        processProtection?.enforce()

        do {
            try await claudeLauncher()
        } catch let error as ClaudeSafeLaunchError {
            record("Не удалось запустить Claude", detail: error.localizedDescription, kind: .warning)
            throw error
        } catch {
            record("Не удалось запустить Claude", detail: "macOS отклонила запрос запуска.", kind: .warning)
            throw ClaudeSafeLaunchError.launchFailed
        }

        guard externalGeneration == launchGeneration,
              confirmedAt == launchConfirmation,
              canLaunchAfterRequest else {
            processProtection?.pause("Состояние сети изменилось во время запуска Claude.")
            processProtection?.enforce()
            record("Claude поставлен на паузу", detail: "Состояние защиты изменилось во время запуска.", kind: .warning)
            throw ClaudeSafeLaunchError.protectionChanged
        }
        processProtection?.enforce()
        refreshDiagnostics()
        record("Claude запущен под контролем", detail: "На момент запуска разрешённая страна была подтверждена. Это защита на уровне процесса, не сетевой kill switch.")
    }

    private var canLaunchAfterRequest: Bool {
        !isSleeping && watchdogHealthy
            && network.connectivity == .available
            && desktopPolicyAllowsLaunch
            && (!requiresClaudeRoutes || claudeRoutes.pauseReason(vpnLocation: preferences.vpnLocation) == nil)
            && (!startsMonitoring || routeObserver.isMonitoring)
    }

    private var desktopPolicyAllowsLaunch: Bool {
        guard recovery.isReady, processProtection != nil, currentObservation != nil, tunnelPauseReason == nil else { return false }
        if case .failed = processProtection?.status { return false }
        if preferences.accessConfiguration != nil { return accessDecision(for: .desktop).allowed }
        return protection == .countryConfirmed && currentObservation?.countryCode == preferences.allowedCountryCode
    }

    // Presentation uses the same freshness boundary as enforcement, never a
    // separate cached success that could outlive the actual permission.
    var confirmedEgressObservation: EgressObservation? { currentObservation }

    private var currentObservation: EgressObservation? {
        guard let confirmedAt,
              now().timeIntervalSince(confirmedAt) >= 0,
              now().timeIntervalSince(confirmedAt) < confirmationLifetime else { return nil }
        switch externalCheck {
        case .observed(let observation):
            return processProtection == nil ? observation : protectionObservation
        case .checking:
            // A planned refresh does not revoke the previous unexpired lease.
            // Route callbacks still enforce that lease; network changes and
            // failed requests explicitly clear it before reaching this guard.
            return processProtection == nil ? nil : protectionObservation
        default:
            return nil
        }
    }

    private var tunnelPauseReason: String? {
        guard requiresTunnelChecks, preferences.vpnLocation == .thisMac else { return nil }
        guard let tunnel = verifiedTunnel else { return "Владелец и интерфейс туннеля не подтверждены." }
        if let snapshot = claudeRoutes.state.snapshot, snapshot.routes.contains(where: { route in
            if case .localPeer = route.path { return false }
            return route.routeInterface != tunnel.interface || route.sourceInterfaces != [tunnel.interface]
        }) {
            return "Соединение Claude не соответствует выбранному туннелю VPN."
        }
        return nil
    }

    private func applyProtectionPolicy() {
        guard let processProtection else { return }
        guard !startsMonitoring || routeObserver.isMonitoring else {
            processProtection.pause("Не удалось включить наблюдение за маршрутами сети. Claude остаётся на паузе.")
            return
        }
        guard watchdogHealthy else {
            processProtection.pause("Наблюдатель восстановления недоступен. Claude остаётся на паузе.")
            return
        }
        if needsRuleSetup {
            processProtection.requireCountry(currentCountryCode: currentObservation?.countryCode)
            return
        }
        guard !isSleeping else {
            processProtection.pause("Mac спит. Ждём свежие проверки после пробуждения.")
            return
        }
        if requiresClaudeRoutes, let reason = claudeRoutes.pauseReason(vpnLocation: preferences.vpnLocation) {
            processProtection.pause(reason)
            return
        }
        if let reason = tunnelPauseReason {
            recovery.reset()
            nextAutomaticCheckAt = .distantPast
            processProtection.pause(reason)
            return
        }
        if let observation = currentObservation {
            guard recovery.isReady else {
                processProtection.pause("Проверяем устойчивость подключения: \(recoveryProgress).")
                return
            }
            if preferences.accessConfiguration != nil {
                let decisions = Dictionary(uniqueKeysWithValues: ProtectedApplication.allCases.map { ($0, accessDecision(for: $0)) })
                processProtection.apply(decisions, country: observation.countryCode)
            } else {
                processProtection.apply(observation, allowedCountryCode: preferences.allowedCountryCode)
            }
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

    func updateWatchdogHealth(_ healthy: Bool) {
        guard watchdogHealthy != healthy else { return }
        watchdogHealthy = healthy
        if healthy {
            applyProtectionPolicy()
        } else {
            processProtection?.pause("Наблюдатель восстановления недоступен. Claude остаётся на паузе.")
            recordWatchdogError("Защита требует внимания", detail: "Наблюдатель восстановления не работает. Claude приостановлен.")
        }
    }

    private func updateAutostart(_ enabled: Bool) {
        guard startsMonitoring else { return }
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            recordWatchdogError("Автозапуск", detail: enabled ? "Не удалось включить: \(error.localizedDescription)" : "Не удалось отключить: \(error.localizedDescription)")
        }
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
