import ArmourCore
import Combine
import Foundation

enum TrafficIndexState: Equatable {
    case off
    case sampling
    case observed(TrafficSnapshot)
    case failed(String)
    case sleeping

    var snapshot: TrafficSnapshot? {
        if case .observed(let value) = self { return value }
        return nil
    }

    var title: String {
        switch self {
        case .off: return "Наблюдение выключено"
        case .sampling: return "Читаем соединения…"
        case .observed(let value): return "\(value.connections.count) соединений · \(value.isPartial ? "неполный снимок" : "снимок сокетов")"
        case .failed: return "Снимок недоступен"
        case .sleeping: return "Приостановлено на время сна"
        }
    }
}

@MainActor
final class TrafficMonitor: ObservableObject {
    typealias Reader = @Sendable () async throws -> TrafficSnapshot
    @Published private(set) var state = TrafficIndexState.off
    @Published private(set) var isEnabled = false
    private var isSleeping = false
    private var generation = UUID()
    private var task: Task<Void, Never>?
    private let reader: Reader
    private let interval: UInt64

    init(interval: UInt64 = 5_000_000_000, reader: @escaping Reader = { try await SocketTrafficReader.snapshot() }) {
        self.reader = reader
        self.interval = interval
    }

    deinit { task?.cancel() }

    /// Explicit local consent only; enablement is deliberately not persisted.
    func start() {
        guard !isEnabled else { return }
        isEnabled = true
        restart()
    }

    func stop() {
        isEnabled = false
        cancel()
        state = .off
    }

    func refresh() {
        guard isEnabled, !isSleeping else { return }
        restart()
    }

    func prepareForSleep() {
        isSleeping = true
        cancel()
        state = isEnabled ? .sleeping : .off
    }

    func resumeAfterWake() {
        isSleeping = false
        if isEnabled { restart() }
    }

    private func cancel() {
        generation = UUID()
        task?.cancel()
        task = nil
    }

    private func restart() {
        cancel()
        guard !isSleeping else { state = .sleeping; return }
        state = .sampling
        let generation = generation
        let reader = reader
        let interval = interval
        task = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    let snapshot = try await reader()
                    guard !Task.isCancelled, self?.generation == generation else { return }
                    self?.state = .observed(snapshot)
                } catch {
                    guard !Task.isCancelled, self?.generation == generation else { return }
                    self?.state = .failed((error as? TrafficReadError)?.errorDescription
                        ?? "Не удалось получить снимок. Старые адреса очищены; можно повторить проверку.")
                }
                do { try await Task.sleep(nanoseconds: interval) }
                catch { return }
            }
        }
    }
}
