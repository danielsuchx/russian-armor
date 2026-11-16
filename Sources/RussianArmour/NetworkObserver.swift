import ArmourCore
import Foundation
import Network

@MainActor
final class NetworkObserver {
    var onUpdate: ((NetworkSnapshot) -> Void)?
    private var monitor: NWPathMonitor?
    private var generation = UUID()
    private let queue = DispatchQueue(label: "app.russian-armour.network", qos: .utility)

    func suspend() {
        generation = UUID()
        monitor?.cancel()
        monitor = nil
    }

    func refresh() {
        suspend()
        let currentGeneration = UUID()
        generation = currentGeneration
        let next = NWPathMonitor()
        next.pathUpdateHandler = { [weak self] path in
            let connectivity: Connectivity
            switch path.status {
            case .satisfied: connectivity = .available
            case .requiresConnection: connectivity = .requiresConnection
            case .unsatisfied: connectivity = .unavailable
            @unknown default: connectivity = .unavailable
            }
            let snapshot = NetworkSnapshot(
                connectivity: connectivity,
                availableInterfaces: path.availableInterfaces.map(\.name),
                checkedAt: Date()
            )
            Task { @MainActor [weak self] in
                guard let self, self.generation == currentGeneration else { return }
                self.onUpdate?(snapshot)
            }
        }
        monitor = next
        next.start(queue: queue)
    }

    deinit {
        monitor?.cancel()
    }
}
