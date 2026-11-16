import Combine
import Foundation
import LocalAuthentication
import NetworkExtension
import Security
import SystemExtensions

/// Installs only the Claude per-app channel. It never stops that channel when the UI exits.
/// An enabled channel is deliberately not presented as a tested, comprehensive protection claim.
@MainActor
final class ProtectionController: NSObject, ObservableObject {
    static let providerIdentifier = "app.russian-armour.desktop.proxy"
    static let routerTLSName = "russian-armour.router"
    private static let anthropicTeam = "Q6L2SF6YDW"
    private static let applicationIdentifiers = ["com.anthropic.claudefordesktop", "com.anthropic.claude-code"]
    private static let pendingKey = "armour.protection.pending.v1"
    private static let cleanupKey = "armour.protection.credential-cleanup.v1"

    enum Status: Equatable {
        case checking
        case unavailable(String)
        case configurationRequired
        case readyToInstall
        case installing
        case removing
        case approvalRequired
        case restartRequired
        case starting
        case channelEnabled
        case failed(String)

        var title: String {
            switch self {
            case .checking: return "Проверяем системный канал…"
            case .unavailable: return "Нужна подписанная сборка"
            case .configurationRequired: return "Подключите роутер"
            case .readyToInstall: return "Готово к включению"
            case .installing: return "Устанавливаем системный канал…"
            case .removing: return "Удаляем системный канал…"
            case .approvalRequired: return "Подтвердите запрос macOS"
            case .restartRequired: return "Перезагрузите Mac"
            case .starting: return "Подключаем системный канал…"
            case .channelEnabled: return "Системный канал включён · перезапустите Claude"
            case .failed: return "Ошибка системного канала"
            }
        }

        var detail: String {
            switch self {
            case .checking: return "Проверяем расширение и его ответ."
            case .unavailable(let message), .failed(let message): return message
            case .configurationRequired: return "Нужны адрес защищённого канала роутера, сертификат и пароль."
            case .readyToInstall: return "macOS один раз запросит разрешение установить сетевое расширение."
            case .installing: return "Дождитесь ответа macOS."
            case .removing: return "Убираем только подключение Russian Armour. После удаления Claude сможет подключаться напрямую."
            case .approvalRequired: return "Подтвердите изменение сетевого расширения Russian Armour в настройках macOS."
            case .restartRequired: return "macOS завершит изменение сетевого расширения после перезагрузки."
            case .starting: return "Ждём подтверждения от сетевого расширения."
            case .channelEnabled: return "Новые соединения Claude направляются в системный канал. Старые соединения нужно закрыть перезапуском Claude. Полная проверка защиты ещё не выполнена."
            }
        }
    }

    struct EndpointDescriptor: Codable, Equatable {
        let version: Int
        let host: String
        let port: UInt16
        let username: String
        let routerCertificateSHA256: String
    }

    private struct Configuration: Codable {
        let identifier: String
        let endpoint: EndpointDescriptor
        let passwordReference: Data
    }

    enum ControllerError: LocalizedError {
        case invalidConfiguration(String)
        case unsupportedBuild(String)
        case keychain(OSStatus)
        case alreadyWorking
        case activation(Int)
        case deactivation(Int)
        case credentialCleanup(OSStatus)
        case rebootRequired
        case preferences
        case invalidHeartbeat
        case heartbeatTimeout

        var errorDescription: String? {
            switch self {
            case .invalidConfiguration(let message), .unsupportedBuild(let message): return message
            case .keychain(let code): return "Не удалось сохранить пароль в Связке ключей (код \(code))."
            case .alreadyWorking: return "Дождитесь завершения текущего действия."
            case .activation(let code): return "macOS не активировала расширение (код \(code)). Проверьте разрешение в системных настройках."
            case .deactivation(let code): return "Подключение Claude удалено, но macOS не удалила расширение (код \(code)). Повторите удаление."
            case .credentialCleanup(let code): return "Подключение Claude удалено, но пароль не удалён из Связки ключей (код \(code)). Повторите удаление."
            case .rebootRequired: return "Для завершения установки нужно перезагрузить Mac."
            case .preferences: return "Не удалось прочитать или сохранить настройки системного канала."
            case .invalidHeartbeat: return "Расширение не подтвердило готовность защищённого канала."
            case .heartbeatTimeout: return "Сетевое расширение не ответило. Защита не подтверждена."
            }
        }
    }

    @Published private(set) var status: Status = .checking
    @Published private(set) var endpointHost: String?
    @Published private(set) var endpointPort: UInt16?

    private let bundle: Bundle
    private let defaults: UserDefaults
    private var pending: Configuration?
    private var manager: NEAppProxyProviderManager?
    private var subscriptions = Set<AnyCancellable>()
    private var isBusy = false
    private var recovery = RecoveryPolicy()
    private var activationRequest: OSSystemExtensionRequest?
    private var extensionOperationIsRemoval = false
    private var activationContinuation: CheckedContinuation<Void, Error>?

    init(bundle: Bundle = .main, defaults: UserDefaults = .standard, automaticallyRefresh: Bool = true) {
        self.bundle = bundle
        self.defaults = defaults
        if let data = defaults.data(forKey: Self.pendingKey), data.count <= 16_384,
           let saved = try? JSONDecoder().decode(Configuration.self, from: data),
           (try? Self.validate(saved.endpoint)) != nil, UUID(uuidString: saved.identifier) != nil,
           !saved.passwordReference.isEmpty {
            pending = saved
            endpointHost = saved.endpoint.host
            endpointPort = saved.endpoint.port
        }
        super.init()
        if automaticallyRefresh {
            NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)
                .receive(on: RunLoop.main)
                .sink { [weak self] _ in Task { await self?.refresh() } }
                .store(in: &subscriptions)
            Timer.publish(every: 5, on: .main, in: .common)
                .autoconnect()
                .sink { [weak self] _ in Task { await self?.refresh() } }
                .store(in: &subscriptions)
            Task { [weak self] in await self?.refresh() }
        }
    }

    /// Only metadata and an opaque Keychain item reference are persisted in preferences.
    /// The password itself is a shared, non-synchronizing Keychain item.
    func configure(host: String, port: UInt16, username: String, password: String,
                   routerCertificateSHA256: String) async throws {
        guard !isBusy else { throw ControllerError.alreadyWorking }
        isBusy = true
        defer { isBusy = false }
        do {
            let endpoint = EndpointDescriptor(version: 1, host: host.trimmingCharacters(in: .whitespacesAndNewlines),
                                              port: port, username: username,
                                              routerCertificateSHA256: routerCertificateSHA256.lowercased())
            try Self.validate(endpoint)
            guard !password.isEmpty, password.utf8.count <= 255, !password.utf8.contains(0) else {
                throw ControllerError.invalidConfiguration("Пароль должен содержать от 1 до 255 байт без нулевых символов.")
            }
            try signingPreflight()
            let group = try keychainAccessGroup()
            let reference = try Self.storePassword(password, accessGroup: group)
            let configuration = Configuration(identifier: UUID().uuidString, endpoint: endpoint, passwordReference: reference)
            do {
                defaults.set(try JSONEncoder().encode(configuration), forKey: Self.pendingKey)
            } catch {
                Self.deletePassword(reference)
                throw ControllerError.preferences
            }
            pending = configuration
            endpointHost = endpoint.host
            endpointPort = endpoint.port
            recovery = RecoveryPolicy()
            status = .readyToInstall
        } catch {
            if case ControllerError.unsupportedBuild(let message) = error {
                status = .unavailable(message)
            } else {
                status = .failed(Self.safeMessage(error))
            }
            throw error
        }
    }

    /// The descriptor contains no password or private key. The password is supplied separately.
    func configure(descriptorURL: URL, password: String) async throws {
        let resource = try descriptorURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard resource.isRegularFile == true, let count = resource.fileSize, count > 0, count <= 16_384 else {
            throw ControllerError.invalidConfiguration("Выберите небольшой JSON-файл подключения к роутеру.")
        }
        let descriptor: EndpointDescriptor
        do {
            let handle = try FileHandle(forReadingFrom: descriptorURL)
            defer { try? handle.close() }
            guard let data = try handle.read(upToCount: 16_385), data.count <= 16_384 else {
                throw ControllerError.invalidConfiguration("Файл подключения слишком большой.")
            }
            descriptor = try JSONDecoder().decode(EndpointDescriptor.self, from: data)
        } catch {
            throw ControllerError.invalidConfiguration("Не удалось прочитать файл подключения к роутеру.")
        }
        try Self.validate(descriptor)
        try await configure(host: descriptor.host, port: descriptor.port, username: descriptor.username,
                            password: password, routerCertificateSHA256: descriptor.routerCertificateSHA256)
    }

    func installAndEnable() async throws {
        guard !isBusy else { throw ControllerError.alreadyWorking }
        recovery.installationAttempted = true
        isBusy = true
        defer { isBusy = false }
        do {
            try signingPreflight()
            guard bundle.bundleURL.standardizedFileURL.path.hasPrefix("/Applications/") else {
                throw ControllerError.unsupportedBuild("Переместите подписанное приложение Russian Armour в папку «Программы», затем повторите включение.")
            }
            let existing = try await loadManager()
            let configuration = try pending ?? existing.flatMap(Self.configuration(from:))
                ?? { throw ControllerError.invalidConfiguration("Сначала добавьте подключение к роутеру.") }()
            try Self.validate(configuration.endpoint)
            // Fail before changing network preferences if the shared credential cannot be read.
            try Self.verifyPasswordReference(configuration.passwordReference, accessGroup: keychainAccessGroup())
            status = .installing
            try await activateExtension()

            let previousIdentifier = existing.flatMap(Self.configuration(from:))?.identifier
            let selected = existing ?? NEAppProxyProviderManager()
            let tunnel = NETunnelProviderProtocol()
            tunnel.providerBundleIdentifier = Self.providerIdentifier
            tunnel.serverAddress = configuration.endpoint.host
            tunnel.username = configuration.endpoint.username
            tunnel.passwordReference = configuration.passwordReference
            tunnel.providerConfiguration = [
                "version": 1,
                "configurationID": configuration.identifier,
                "host": configuration.endpoint.host,
                "port": Int(configuration.endpoint.port),
                "username": configuration.endpoint.username,
                "routerCertificateSHA256": configuration.endpoint.routerCertificateSHA256,
                "tlsServerName": Self.routerTLSName
            ]
            selected.protocolConfiguration = tunnel
            selected.localizedDescription = "Russian Armour — Claude"
            selected.appRules = Self.applicationRules()
            selected.excludedDomains = []
            selected.safariDomains = []
            selected.mailDomains = []
            selected.calendarDomains = []
            selected.contactsDomains = []
            selected.associatedDomains = []
            // Per-app rules themselves trigger on-demand. Disconnect rules would permit bypass.
            selected.onDemandRules = []
            selected.isOnDemandEnabled = true
            selected.isEnabled = true
            try await selected.saveToPreferences()
            try await selected.loadFromPreferences()
            guard Self.hasRequiredRules(selected),
                  let session = selected.connection as? NETunnelProviderSession else {
                throw ControllerError.preferences
            }
            manager = selected
            pending = nil
            defaults.removeObject(forKey: Self.pendingKey)
            status = .starting
            if previousIdentifier != configuration.identifier, session.status != .disconnected, session.status != .invalid {
                session.stopTunnel()
                for _ in 0..<40 {
                    if session.status == .disconnected || session.status == .invalid { break }
                    try await Task.sleep(nanoseconds: 250_000_000)
                }
                guard session.status == .disconnected || session.status == .invalid else {
                    throw ControllerError.preferences
                }
            }
            if session.status != .connected && session.status != .connecting && session.status != .reasserting {
                recovery.lastStartAttempt = Date()
                try session.startTunnel(options: nil)
            }
            // A connected preference alone never promotes the UI. refresh requires a provider reply.
            if session.status == .connected { try await verifyRuntime(session, expectedIdentifier: configuration.identifier) }
        } catch ControllerError.rebootRequired {
            status = .restartRequired
            throw ControllerError.rebootRequired
        } catch {
            if case ControllerError.unsupportedBuild(let message) = error {
                status = .unavailable(message)
            } else {
                status = .failed(Self.safeMessage(error))
            }
            throw error
        }
    }

    /// Explicit reversal of installation. Only configurations owned by this containing app and
    /// targeting its provider are touched. Exiting the UI never calls this method.
    func removeProtection() async throws {
        guard !isBusy else { throw ControllerError.alreadyWorking }
        isBusy = true
        defer { isBusy = false }
        do {
            // Unlike installation, removing a stranded config must not require an embedded
            // extension/profile that might have been removed or expired in an app update.
            try removalPreflight()
            status = .removing
            let owned = try await loadOwnedManagers()
            var credentialReferences = Set<Data>()
            if let data = defaults.data(forKey: Self.cleanupKey), data.count <= 65_536,
               let previous = try? JSONDecoder().decode([Data].self, from: data), previous.count <= 128 {
                credentialReferences.formUnion(previous)
            }
            if let reference = pending?.passwordReference { credentialReferences.insert(reference) }
            for selected in owned {
                let reference = (selected.protocolConfiguration as? NETunnelProviderProtocol)?.passwordReference
                selected.isOnDemandEnabled = false
                selected.isEnabled = false
                try await selected.saveToPreferences()
                // Removing the saved per-app rule is what restores the system's normal routing.
                // Do not delete the credential while an installed manager may still need it.
                try await selected.removeFromPreferences()
                if let reference { credentialReferences.insert(reference) }
                defaults.set(try JSONEncoder().encode(Array(credentialReferences)), forKey: Self.cleanupKey)
            }
            manager = nil
            // Keep only opaque refs until deletion succeeds; a Keychain error must be retryable
            // even though its former manager has already been removed.
            defaults.set(try JSONEncoder().encode(Array(credentialReferences)), forKey: Self.cleanupKey)
            var cleanupError: OSStatus?
            for reference in credentialReferences {
                let code = Self.deletePassword(reference)
                if code != errSecSuccess && code != errSecItemNotFound { cleanupError = code }
            }
            if let cleanupError {
                // Keep pending metadata/ref for a retry; it contains no password.
                throw ControllerError.credentialCleanup(cleanupError)
            }
            defaults.removeObject(forKey: Self.cleanupKey)
            pending = nil
            defaults.removeObject(forKey: Self.pendingKey)
            endpointHost = nil
            endpointPort = nil
            try await changeExtension(removing: true)
            status = .configurationRequired
        } catch ControllerError.rebootRequired {
            status = .restartRequired
            throw ControllerError.rebootRequired
        } catch {
            if case ControllerError.unsupportedBuild(let message) = error {
                status = .unavailable(message)
            } else {
                status = .failed(Self.safeMessage(error))
            }
            throw error
        }
    }

    /// Automatic installation is attempted once per launch/configuration. Connection recovery
    /// continues without UI interaction; OS approval requests are never retried by the timer.
    struct RecoveryPolicy {
        enum Action: Equatable { case configure, install, start, verify, wait }
        var installationAttempted = false
        var lastStartAttempt: Date?

        mutating func action(hasPending: Bool, hasManager: Bool, rulesValid: Bool,
                             enabled: Bool, sessionStatus: NEVPNStatus, now: Date) -> Action {
            if hasPending || (hasManager && (!rulesValid || !enabled)) {
                guard !installationAttempted else { return .wait }
                installationAttempted = true
                return .install
            }
            guard hasManager else { return .configure }
            switch sessionStatus {
            case .connected:
                lastStartAttempt = nil
                return .verify
            case .disconnected, .invalid:
                guard lastStartAttempt.map({ now.timeIntervalSince($0) >= 30 }) ?? true else { return .wait }
                lastStartAttempt = now
                return .start
            default:
                return .wait
            }
        }
    }

    func refresh() async {
        guard !isBusy, status != .restartRequired else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try signingPreflight()
            let selected = try await loadManager()
            manager = selected
            if pending == nil, let selected, let configuration = Self.configuration(from: selected) {
                endpointHost = configuration.endpoint.host
                endpointPort = configuration.endpoint.port
            }
            let session = selected?.connection as? NETunnelProviderSession
            let action = recovery.action(
                hasPending: pending != nil, hasManager: selected != nil,
                rulesValid: selected.map(Self.hasRequiredRules) ?? false,
                enabled: selected?.isEnabled ?? false, sessionStatus: session?.status ?? .invalid, now: Date())
            switch action {
            case .configure:
                status = .configurationRequired
            case .install:
                // Hand the busy lock to the same installation path used by explicit retry.
                isBusy = false
                try await installAndEnable()
            case .start:
                guard let session else { throw ControllerError.preferences }
                status = .starting
                try session.startTunnel(options: nil)
            case .verify:
                guard let session, let selected, let configuration = Self.configuration(from: selected) else {
                    throw ControllerError.preferences
                }
                try await verifyRuntime(session, expectedIdentifier: configuration.identifier)
            case .wait:
                if session?.status == .connecting || session?.status == .reasserting || session?.status == .disconnecting {
                    status = .starting
                }
            }
        } catch ControllerError.rebootRequired {
            status = .restartRequired
        } catch ControllerError.unsupportedBuild(let message) {
            status = .unavailable(message)
        } catch {
            status = .failed(Self.safeMessage(error))
        }
    }

    static func validate(_ endpoint: EndpointDescriptor) throws {
        let host = endpoint.host
        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        let bytes = octets.compactMap { value -> UInt8? in
            guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                  value.count == 1 || value.first != "0" else { return nil }
            return UInt8(value)
        }
        let isPrivate = bytes.count == 4 && (bytes[0] == 10
            || bytes[0] == 172 && (16...31).contains(bytes[1])
            || bytes[0] == 192 && bytes[1] == 168)
        guard endpoint.version == 1, octets.count == 4, isPrivate, endpoint.port != 0 else {
            throw ControllerError.invalidConfiguration("Укажите локальный IPv4-адрес роутера и порт от 1 до 65535 без URL и пути.")
        }
        guard !endpoint.username.isEmpty, endpoint.username.utf8.count <= 255,
              !endpoint.username.utf8.contains(0) else {
            throw ControllerError.invalidConfiguration("Имя пользователя должно содержать от 1 до 255 байт без нулевых символов.")
        }
        guard endpoint.routerCertificateSHA256.utf8.count == 64,
              endpoint.routerCertificateSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ControllerError.invalidConfiguration("Нужен SHA-256 отпечаток сертификата роутера: 64 шестнадцатеричных символа.")
        }
    }

    private static func applicationRules() -> [NEAppRule] {
        applicationIdentifiers.map { identifier in
            let rule = NEAppRule(signingIdentifier: identifier, designatedRequirement: requirement(identifier))
            rule.matchTools = nil
            return rule
        }
    }

    private static func requirement(_ identifier: String) -> String {
        "identifier \"\(identifier)\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(anthropicTeam)\""
    }

    private static func hasRequiredRules(_ selected: NEAppProxyProviderManager) -> Bool {
        guard selected.routingMethod == .sourceApplication,
              selected.isOnDemandEnabled, selected.onDemandRules?.isEmpty != false,
              selected.excludedDomains.isEmpty, selected.safariDomains.isEmpty, selected.mailDomains.isEmpty,
              selected.calendarDomains.isEmpty, selected.contactsDomains.isEmpty, selected.associatedDomains.isEmpty,
              selected.appRules.count == applicationIdentifiers.count,
              configuration(from: selected) != nil else { return false }
        return applicationIdentifiers.allSatisfy { identifier in
            selected.appRules.contains { rule in
                rule.matchSigningIdentifier == identifier && rule.matchDesignatedRequirement == requirement(identifier)
                    && rule.matchPath == nil && rule.matchDomains?.isEmpty != false && rule.matchTools == nil
            }
        }
    }

    private static func configuration(from selected: NEAppProxyProviderManager) -> Configuration? {
        guard let tunnel = selected.protocolConfiguration as? NETunnelProviderProtocol,
              tunnel.providerBundleIdentifier == providerIdentifier,
              let values = tunnel.providerConfiguration,
              values["version"] as? Int == 1, values["tlsServerName"] as? String == routerTLSName,
              let identifier = values["configurationID"] as? String, UUID(uuidString: identifier) != nil,
              let host = values["host"] as? String, let port = values["port"] as? Int,
              let parsedPort = UInt16(exactly: port), let username = values["username"] as? String,
              let pin = values["routerCertificateSHA256"] as? String,
              let reference = tunnel.passwordReference, !reference.isEmpty else { return nil }
        let endpoint = EndpointDescriptor(version: 1, host: host, port: parsedPort, username: username,
                                          routerCertificateSHA256: pin)
        guard (try? validate(endpoint)) != nil else { return nil }
        return Configuration(identifier: identifier, endpoint: endpoint, passwordReference: reference)
    }

    private func loadOwnedManagers() async throws -> [NEAppProxyProviderManager] {
        // The API returns only this app's saved configurations; additionally restrict by provider.
        let all = try await NEAppProxyProviderManager.loadAllFromPreferences()
        return all.filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerIdentifier }
    }

    private func loadManager() async throws -> NEAppProxyProviderManager? {
        let matching = try await loadOwnedManagers()
        guard matching.count <= 1 else { throw ControllerError.preferences }
        return matching.first
    }

    private func verifyRuntime(_ session: NETunnelProviderSession, expectedIdentifier: String) async throws {
        let request = Data(#"{"version":1,"command":"status"}"#.utf8)
        let reply: Data = try await withCheckedThrowingContinuation { continuation in
            let gate = ProviderReply(continuation: continuation)
            gate.armTimeout()
            do {
                try session.sendProviderMessage(request) { data in
                    Task { @MainActor in gate.finish(data.map(Result.success) ?? .failure(ControllerError.invalidHeartbeat)) }
                }
            } catch {
                gate.finish(.failure(ControllerError.invalidHeartbeat))
            }
        }
        guard Self.acceptsHeartbeat(reply, configurationID: expectedIdentifier), session.status == .connected else {
            throw ControllerError.invalidHeartbeat
        }
        status = .channelEnabled
    }

    /// A reply from an older session or different relay transport cannot bless the current config.
    static func acceptsHeartbeat(_ data: Data, configurationID: String) -> Bool {
        struct Heartbeat: Decodable { let version: Int; let ready: Bool; let configurationID: String; let transport: String }
        guard data.count <= 4096, UUID(uuidString: configurationID) != nil,
              let heartbeat = try? JSONDecoder().decode(Heartbeat.self, from: data) else { return false }
        return heartbeat.version == 1 && heartbeat.ready && heartbeat.configurationID == configurationID
            && heartbeat.transport == "tls-pinned-socks5"
    }

    private func activateExtension() async throws {
        try await changeExtension(removing: false)
    }

    private func changeExtension(removing: Bool) async throws {
        try await withCheckedThrowingContinuation { continuation in
            activationContinuation = continuation
            extensionOperationIsRemoval = removing
            let request = removing
                ? OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: Self.providerIdentifier, queue: .main)
                : OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.providerIdentifier, queue: .main)
            activationRequest = request
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func finishActivation(_ request: OSSystemExtensionRequest, result: Result<Void, Error>) {
        guard request === activationRequest else { return }
        let continuation = activationContinuation
        activationContinuation = nil
        activationRequest = nil
        continuation?.resume(with: result)
    }

    private func keychainAccessGroup() throws -> String {
        guard let group = bundle.object(forInfoDictionaryKey: "ArmourKeychainAccessGroup") as? String,
              group.hasSuffix(".app.russian-armour.shared"), !group.contains("$("), group.split(separator: ".").first?.count == 10 else {
            throw ControllerError.unsupportedBuild("В сборке не настроена общая Связка ключей приложения и сетевого расширения.")
        }
        return group
    }

    private static func storePassword(_ password: String, accessGroup: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "app.russian-armour.proxy.credentials",
            kSecAttrAccount as String: UUID().uuidString,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(password.utf8),
            kSecReturnPersistentRef as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
        var result: CFTypeRef?
        let code = SecItemAdd(query as CFDictionary, &result)
        guard code == errSecSuccess, let reference = result as? Data else { throw ControllerError.keychain(code) }
        return reference
    }

    private static func verifyPasswordReference(_ reference: Data, accessGroup: String) throws {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValuePersistentRef as String: reference,
            kSecAttrService as String: "app.russian-armour.proxy.credentials",
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecUseDataProtectionKeychain as String: true
        ]
        let code = SecItemCopyMatching(query as CFDictionary, nil)
        guard code == errSecSuccess else { throw ControllerError.keychain(code) }
    }

    @discardableResult
    private static func deletePassword(_ reference: Data) -> OSStatus {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecValuePersistentRef as String: reference,
                       kSecAttrService as String: "app.russian-armour.proxy.credentials",
                       kSecUseDataProtectionKeychain as String: true] as CFDictionary)
    }

    private func removalPreflight() throws {
        let info = try Self.signingInfo(bundle.bundleURL)
        guard let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              entitlements["com.apple.developer.system-extension.install"] as? Bool == true,
              Self.hasProxyEntitlement(entitlements) else {
            throw ControllerError.unsupportedBuild("Для удаления системного канала откройте подписанную сборку Russian Armour.")
        }
    }

    private func signingPreflight() throws {
        let extensionURL = bundle.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(Self.providerIdentifier).systemextension", isDirectory: true)
        guard let extensionBundle = Bundle(url: extensionURL), extensionBundle.bundleIdentifier == Self.providerIdentifier else {
            throw ControllerError.unsupportedBuild("Эта сборка не содержит сетевого расширения. Нужна подписанная сборка Russian Armour с системным каналом.")
        }
        let hostInfo = try Self.signingInfo(bundle.bundleURL)
        let extensionInfo = try Self.signingInfo(extensionURL)
        guard let team = hostInfo[kSecCodeInfoTeamIdentifier as String] as? String,
              extensionInfo[kSecCodeInfoTeamIdentifier as String] as? String == team,
              let hostEntitlements = hostInfo[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let extensionEntitlements = extensionInfo[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              hostEntitlements["com.apple.developer.system-extension.install"] as? Bool == true else {
            throw ControllerError.unsupportedBuild("Подпись приложения и расширения не содержит необходимых разрешений macOS.")
        }
        let group = try keychainAccessGroup()
        guard group == "\(team).app.russian-armour.shared",
              (hostEntitlements["keychain-access-groups"] as? [String])?.contains(group) == true,
              (extensionEntitlements["keychain-access-groups"] as? [String])?.contains(group) == true else {
            throw ControllerError.unsupportedBuild("Подпись не разрешает общую Связку ключей приложения и расширения.")
        }
        guard Self.hasProxyEntitlement(hostEntitlements), Self.hasProxyEntitlement(extensionEntitlements) else {
            throw ControllerError.unsupportedBuild("Для этой сборки не разрешён системный сетевой канал Network Extension.")
        }
        for item in [bundle.bundleURL, extensionURL] {
            guard FileManager.default.fileExists(atPath: item.appendingPathComponent("Contents/embedded.provisionprofile").path) else {
                throw ControllerError.unsupportedBuild("В сборке отсутствует provisioning profile Apple для Network Extension.")
            }
        }
    }

    private static func hasProxyEntitlement(_ entitlements: [String: Any]) -> Bool {
        let values = entitlements["com.apple.developer.networking.networkextension"] as? [String] ?? []
        if values.contains("app-proxy-provider-systemextension") { return true }
        // Apple Development profiles may grant the unsuffixed value. Distribution must use the
        // Developer ID system-extension value; OS activation verifies the profile's signature.
        return values.contains("app-proxy-provider") && (entitlements["get-task-allow"] as? Bool == true
            || entitlements["com.apple.security.get-task-allow"] as? Bool == true)
    }

    private static func signingInfo(_ url: URL) throws -> [String: Any] {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            throw ControllerError.unsupportedBuild("Подпись приложения или расширения недействительна.")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any], let flags = values[kSecCodeInfoFlags as String] as? UInt32,
              flags & SecCodeSignatureFlags.adhoc.rawValue == 0,
              values[kSecCodeInfoTeamIdentifier as String] as? String != nil else {
            throw ControllerError.unsupportedBuild("Локальная ad-hoc подпись не позволяет установить сетевое расширение. Нужны подпись Apple и provisioning profile.")
        }
        return values
    }

    private static func safeMessage(_ error: Error) -> String {
        (error as? ControllerError)?.errorDescription ?? "macOS не выполнила действие с системным каналом. Повторите попытку в подписанной сборке."
    }

    private final class ProviderReply {
        private var continuation: CheckedContinuation<Data, Error>?
        private var timeout: Task<Void, Never>?
        init(continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
        func armTimeout() {
            timeout = Task {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { return }
                finish(.failure(ControllerError.heartbeatTimeout))
            }
        }
        func finish(_ result: Result<Data, Error>) {
            guard let continuation else { return }
            self.continuation = nil
            timeout?.cancel()
            timeout = nil
            continuation.resume(with: result)
        }
    }
}

extension ProtectionController: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        existing.bundleIdentifier == "app.russian-armour.desktop.proxy" && replacement.bundleIdentifier == "app.russian-armour.desktop.proxy" ? .replace : .cancel
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor [weak self] in
            guard let self, request === self.activationRequest else { return }
            self.status = .approvalRequired
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            switch result {
            case .completed: self.finishActivation(request, result: .success(()))
            case .willCompleteAfterReboot: self.finishActivation(request, result: .failure(ControllerError.rebootRequired))
            @unknown default: self.finishActivation(request, result: .failure(ControllerError.activation(0)))
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor [weak self] in
            guard let self, request === self.activationRequest else { return }
            let failure = error as NSError
            if self.extensionOperationIsRemoval {
                if failure.domain == OSSystemExtensionErrorDomain,
                   failure.code == OSSystemExtensionError.extensionNotFound.rawValue {
                    self.finishActivation(request, result: .success(()))
                } else {
                    self.finishActivation(request, result: .failure(ControllerError.deactivation(failure.code)))
                }
            } else {
                self.finishActivation(request, result: .failure(ControllerError.activation(failure.code)))
            }
        }
    }
}
