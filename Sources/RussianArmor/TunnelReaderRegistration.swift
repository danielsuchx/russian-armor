import ArmorTunnel
import ServiceManagement
import SwiftUI

@MainActor
final class TunnelReaderRegistration: ObservableObject {
    @Published private(set) var status = ClashTunnelService.service.status
    @Published private(set) var busy = false
    @Published private(set) var message: String?

    private let service = ClashTunnelService.service
    private let defaults = UserDefaults.standard
    private let buildKey = "armor.tunnelReader.registeredBuild"
    private var build: String? { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String }

    func refresh() { status = service.status }

    /// An installed ad-hoc build has new code hashes after an update. Rebind
    /// a previously enabled daemon to the new bundle. Preserve macOS opt-out.
    func migrateEnabledReader() async {
        refresh()
        let previousBuild = defaults.string(forKey: buildKey)
        guard let build, !busy, previousBuild != build,
              status == .enabled || (status == .notRegistered && previousBuild != nil) else { return }
        await configure(enable: true)
    }

    func configure(enable: Bool) async {
        guard !busy else { return }
        busy = true
        message = nil
        defer {
            refresh()
            busy = false
        }
        do {
            if service.status == .enabled || service.status == .requiresApproval {
                try await service.unregister()
            }
            if enable {
                try service.register()
                defaults.set(build, forKey: buildKey)
            } else {
                defaults.removeObject(forKey: buildKey)
            }
        } catch {
            message = service.status == .requiresApproval ? "Подтвердите службу в настройках macOS."
                : "Не удалось изменить регистрацию службы: " + error.localizedDescription
        }
    }
}
