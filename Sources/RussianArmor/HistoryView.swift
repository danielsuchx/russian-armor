import ArmorCore
import SwiftUI

struct HistoryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmingClear = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("История событий")
                        .font(.title2.weight(.semibold))
                    Text("До \(EventJournal.capacity) последних событий · только на этом Mac")
                        .font(AppTypography.description)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    confirmingClear = true
                } label: {
                    Label("Очистить…", systemImage: "trash")
                }
                .disabled(model.journal.events.isEmpty)
            }
            .padding(20)
            Divider()
            HStack {
                Text(model.journal.unreadCount == 0 ? "Нет новых событий" : "Новых событий: \(model.journal.unreadCount)")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("history-unread-count")
                Spacer()
                Button("Прочитать всё", action: model.markHistoryRead)
                    .disabled(model.journal.unreadCount == 0)
                    .accessibilityIdentifier("history-mark-read")
            }
            .font(AppTypography.description)
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            Divider()
            if model.journal.events.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 30))
                    Text("История пуста")
                        .font(.headline)
                    Text("Новые события появятся здесь автоматически.")
                        .font(AppTypography.description)
                }
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.journal.events) { event in
                    HStack(alignment: .top, spacing: 12) {
                        Circle()
                            .fill(model.journal.isUnread(event) ? Color.blue : Color.clear)
                            .frame(width: 6, height: 6)
                            .padding(.top, 7)
                            .accessibilityHidden(true)
                        Image(systemName: event.kind.symbol)
                            .foregroundStyle(event.kind == .warning ? Color.orange : Color.secondary)
                            .font(.system(size: 16))
                            .frame(width: 20)
                            .padding(.top, 2)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(event.title)
                                .font(.system(size: 14, weight: .medium))
                            if !event.detail.isEmpty {
                                Text(event.detail)
                                    .font(AppTypography.description)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Text(event.date, format: .dateTime.day().month().hour().minute().second())
                                .font(.system(size: 12))
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 7)
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(model.journal.isUnread(event) ? "Новое событие. " : "")\(event.title). \(event.detail). \(event.date.formatted(date: .abbreviated, time: .standard))")
                }
                .listStyle(.inset)
            }
        }
        .frame(minWidth: 540, minHeight: 360)
        .alert("Очистить историю?", isPresented: $confirmingClear) {
            Button("Отмена", role: .cancel) {}
            Button("Очистить", role: .destructive) { model.clearHistory() }
        } message: {
            Text("Локальная история будет удалена. Это действие нельзя отменить.")
        }
    }
}
