import ArmorCore
import Combine
import Foundation

enum ClaudeRouteState: Equatable {
    case off, checking, sleeping
    case observed(ClaudeRouteSnapshot)
    case failed

    var title: String {
        switch self {
        case .off: return "Наблюдение Claude выключено"
        case .checking: return "Читаем маршруты Claude…"
        case .sleeping: return "Маршруты очищены на время сна"
        case .failed: return "Маршруты Claude недоступны"
        case .observed(let snapshot):
            if snapshot.isPartial { return "Неполный снимок Claude" }
            if snapshot.routes.isEmpty { return "Внешних сокетов не найдено" }
            return "Сокетов Claude: \(snapshot.routes.count)"
        }
    }

    var snapshot: ClaudeRouteSnapshot? {
        if case .observed(let value) = self { return value }
        return nil
    }
}

@MainActor
final class ClaudeRouteMonitor: ObservableObject {
    typealias Reader = @Sendable (Set<TrafficProcess.ID>) async throws -> ClaudeRouteSnapshot
    static let maximumAge: TimeInterval = 5
    @Published private(set) var state = ClaudeRouteState.off
    var onChange: (() -> Void)?
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var enabled = false
    private var sleeping = false
    private let reader: Reader
    private let identities: () -> Set<TrafficProcess.ID>
    private let now: () -> Date
    private let interval: UInt64

    init(interval: UInt64 = 1_000_000_000, now: @escaping () -> Date = Date.init,
         identities: @escaping () -> Set<TrafficProcess.ID>,
         reader: @escaping Reader = { try await ClaudeSocketRouteReader.snapshot(identities: $0) }) {
        self.interval = interval
        self.now = now
        self.identities = identities
        self.reader = reader
    }

    deinit { task?.cancel() }

    func start() {
        guard !enabled else { return }
        enabled = true
        refresh()
    }

    func refresh() {
        cancel()
        guard enabled else { return }
        guard !sleeping else { update(.sleeping); return }
        update(.checking)
        let generation = generation
        let reader = reader
        let interval = interval
        task = Task { [weak self] in
            while !Task.isCancelled {
                guard let targets = self?.identities() else { return }
                do {
                    let snapshot = try await reader(targets)
                    guard !Task.isCancelled, self?.generation == generation else { return }
                    if self?.isFresh(snapshot) == true {
                        self?.update(.observed(snapshot))
                    } else {
                        self?.update(.failed)
                    }
                } catch {
                    guard !Task.isCancelled, self?.generation == generation else { return }
                    self?.update(.failed)
                }
                do { try await Task.sleep(nanoseconds: interval) } catch { return }
            }
        }
    }

    func expire() {
        if let snapshot = state.snapshot, !isFresh(snapshot) { update(.failed) }
    }

    func pauseReason(vpnLocation: VPNLocation) -> String? {
        guard let snapshot = state.snapshot, isFresh(snapshot) else {
            return "Ждём свежий снимок маршрутов Claude."
        }
        return snapshot.pauseReason(vpnLocation: vpnLocation)
    }

    func prepareForSleep() {
        sleeping = true
        cancel()
        update(.sleeping)
    }

    func resumeAfterWake() {
        sleeping = false
        if enabled { refresh() }
    }

    private func isFresh(_ snapshot: ClaudeRouteSnapshot) -> Bool {
        let age = now().timeIntervalSince(snapshot.capturedAt)
        return age >= 0 && age < Self.maximumAge
    }

    private func update(_ state: ClaudeRouteState) {
        guard self.state != state else { return }
        self.state = state
        onChange?()
    }

    private func cancel() {
        generation = UUID()
        task?.cancel()
        task = nil
    }
}
