import ArmorCore
import SwiftUI

struct TrafficView: View {
    @ObservedObject var monitor: TrafficMonitor
    @State private var query = ""
    @State private var onlyIPv6 = false
    @State private var hideLoopback = false

    private var connections: [TrafficConnection] {
        (monitor.state.snapshot?.connections ?? []).filter { row in
            (!onlyIPv6 || row.remote.version == .v6)
                && (!hideLoopback || !row.remote.isLoopback)
                && (query.isEmpty || [row.process.name, String(row.process.id.pid), row.remote.title, row.local.title]
                    .contains { $0.localizedCaseInsensitiveContains(query) })
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Сетевые соединения").font(.title2.weight(.semibold))
                    Label(monitor.state.title, systemImage: "arrow.up.arrow.down")
                        .font(AppTypography.description).foregroundStyle(.secondary)
                }
                Spacer()
                if monitor.isEnabled {
                    Button("Остановить и очистить", action: monitor.stop)
                } else {
                    Button("Начать наблюдение", action: monitor.start)
                }
                Button { monitor.refresh() } label: {
                    Label("Обновить", systemImage: "arrow.clockwise")
                }
                .disabled(!monitor.isEnabled || monitor.state == .sampling || monitor.state == .sleeping)
            }
            Text("Только метаданные сокетов текущего пользователя: процесс, числовые IP и порты. Без содержимого запросов, DNS-запросов и сохранения адресов. При включённой записи сетевых событий несколько внешних адресов подписанного туннеля Happ отмечаются в истории без самих IP; это не счётчик VPN-серверов. «Остановить и очистить» очищает снимок, но не историю; после перезапуска сбор выключен.")
                .font(AppTypography.description).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                TextField("Найти процесс, PID или IP", text: $query).textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                Toggle("Только IPv6", isOn: $onlyIPv6)
                Toggle("Скрыть loopback", isOn: $hideLoopback)
            }
            if case .failed(let message) = monitor.state {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(AppTypography.description).foregroundStyle(.secondary)
                Text("Повторная локальная проверка — через 5 секунд или по кнопке «Обновить».")
                    .font(AppTypography.description).foregroundStyle(.secondary)
            }
            if let snapshot = monitor.state.snapshot {
                HStack {
                    Text("Снимок: \(snapshot.capturedAt.formatted(date: .omitted, time: .standard)) · процессов прочитано: \(snapshot.inspectedProcesses)")
                    Spacer()
                    Text("Показано: \(connections.count) из \(snapshot.connections.count)")
                }
                .font(AppTypography.description).foregroundStyle(.secondary)
                if snapshot.isPartial {
                    Label("Неполный снимок · процессов недоступно: \(snapshot.inaccessibleProcesses), сокетов пропущено: \(snapshot.inaccessibleSockets)\(snapshot.isTruncated ? "; достигнут лимит опроса" : "")",
                          systemImage: "exclamationmark.triangle")
                        .font(AppTypography.description).foregroundStyle(.secondary)
                }
            }
            Table(connections) {
                TableColumn("Процесс") { row in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(row.process.name)
                        Text("PID \(row.process.id.pid)").font(AppTypography.description).foregroundStyle(.secondary)
                    }
                }.width(min: 120, ideal: 155)
                TableColumn("Протокол") { row in Text("\(row.transport.rawValue) · \(row.remote.version.rawValue)") }
                    .width(95)
                TableColumn("Удалённый адрес") { row in Text(row.remote.title).monospaced().textSelection(.enabled) }
                    .width(min: 160, ideal: 230)
                TableColumn("Локальный адрес") { row in Text(row.local.title).monospaced().textSelection(.enabled) }
                    .width(min: 160, ideal: 210)
                TableColumn("Состояние") { row in Text(row.state) }.width(min: 85, ideal: 110)
            }
            .overlay {
                if connections.isEmpty {
                    VStack(spacing: 8) {
                        if monitor.state == .sampling { ProgressView().controlSize(.small) }
                        Text(emptyMessage).foregroundStyle(.secondary)
                    }.allowsHitTesting(false)
                }
            }
            Text("Это периодический снимок, не полный журнал трафика: короткие соединения могут быть пропущены; UDP показан только с заданным peer. Имя процесса не является проверкой подписи приложения. IP и IPv6 не доказывают VPN-маршрут или утечку, в том числе при VPN на роутере. Объём переданных байтов здесь не измеряется.")
                .font(AppTypography.description).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(minWidth: 860, minHeight: 520)
    }

    private var emptyMessage: String {
        switch monitor.state {
        case .off: return "Нажмите «Начать наблюдение», чтобы прочитать локальные соединения."
        case .sampling: return "Получаем новый снимок…"
        case .sleeping: return "Во сне наблюдение приостановлено; старые адреса очищены."
        case .failed: return "Нет актуального снимка."
        case .observed: return query.isEmpty && !onlyIPv6 && !hideLoopback
            ? "Доступных соединений с удалённым адресатом не обнаружено."
            : "Нет соединений, соответствующих фильтрам."
        }
    }
}
