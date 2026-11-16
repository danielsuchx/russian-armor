import ArmourCore
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
                        .font(.caption)
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
            if model.journal.events.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 30))
                    Text("История пуста")
                        .font(.headline)
                    Text("Новые события появятся здесь автоматически.")
                        .font(.callout)
                }
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.journal.events) { event in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: event.kind.symbol)
                            .foregroundStyle(event.kind == .warning ? Color.orange : Color.secondary)
                            .font(.system(size: 16))
                            .frame(width: 20)
                            .padding(.top, 2)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(event.title)
                                .font(.system(size: 13, weight: .medium))
                            if !event.detail.isEmpty {
                                Text(event.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Text(event.date, format: .dateTime.day().month().hour().minute().second())
                                .font(.system(size: 10))
                                .foregroundStyle(.tertiary)
                                .monospacedDigit()
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 7)
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
