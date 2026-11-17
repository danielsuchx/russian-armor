import ArmorCore
import ArmorTunnel
import Foundation

/// Diagnostic only: a tunnel provider's remote socket addresses are not a list
/// of configured VPN servers and do not prove traffic is flowing through them.
@MainActor
final class HappConnectionMonitor {
    typealias OwnerReader = @Sendable () async throws -> [VerifiedTunnel]
    private let ownerReader: OwnerReader
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var confirmations = 0
    private var reported = false
    private var lastSample: Date?
    var onMultipleAddresses: ((Int) -> Void)?

    init(ownerReader: @escaping OwnerReader = {
        let work = Task.detached(priority: .utility) { try TunnelOwnershipReader.read() }
        return try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
    }) {
        self.ownerReader = ownerReader
    }

    deinit { task?.cancel() }

    func receive(_ state: TrafficIndexState, recordsEvents: Bool) {
        generation = UUID()
        task?.cancel()
        task = nil
        guard recordsEvents else { reset(); return }
        switch state {
        case .off:
            reset()
        case .sampling, .failed, .sleeping:
            // Unknown is not evidence that the previous episode ended.
            confirmations = 0
        case .observed(let snapshot):
            guard snapshot.capturedAt != lastSample else { return }
            lastSample = snapshot.capturedAt
            let generation = generation
            let reader = ownerReader
            task = Task { [weak self] in
                do {
                    let tunnels = try await reader()
                    guard !Task.isCancelled, let self, self.generation == generation else { return }
                    guard let count = Self.addressCount(snapshot: snapshot, tunnels: tunnels) else {
                        self.confirmations = 0
                        return
                    }
                    if count > 1 {
                        self.confirmations += 1
                        if self.confirmations >= 2, !self.reported {
                            self.reported = true
                            self.onMultipleAddresses?(count)
                        }
                    } else {
                        self.confirmations = 0
                        if !snapshot.isPartial { self.reported = false }
                    }
                } catch {
                    guard !Task.isCancelled, self?.generation == generation else { return }
                    self?.confirmations = 0
                }
            }
        }
    }

    private func reset() {
        confirmations = 0
        reported = false
        lastSample = nil
    }

    static func addressCount(snapshot: TrafficSnapshot, tunnels: [VerifiedTunnel]) -> Int? {
        // Verified from the installed Happ provider's code-signing metadata.
        // Never attribute connections by a spoofable process name or utun count.
        let owners = Set(tunnels.filter {
            $0.signingID == "su.ffg.happ.tunnel" && $0.teamID == "A6NW69KD84"
        }.map { TrafficProcess.ID(pid: $0.owner.pid, startSeconds: $0.owner.startSeconds,
                                  startMicroseconds: $0.owner.startMicroseconds) })
        guard !owners.isEmpty else { return nil }
        let addresses = snapshot.connections.compactMap { connection -> String? in
            guard owners.contains(connection.process.id), connection.remote.port > 0,
                  connection.transport == .udp || connection.state == "Установлено",
                  let address = IPRange(connection.remote.address)?.value,
                  !nonExternalRanges.contains(where: { $0.contains(address) }) else { return nil }
            return address
        }
        // Ports, transports, duplicate sockets and IPv4-mapped IPv6 don't inflate the count.
        return Set(addresses).count
    }

    private static let nonExternalRanges = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"
    ].compactMap(IPRange.init)
}
