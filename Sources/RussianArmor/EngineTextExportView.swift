import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct EngineTextExportView: View {
    let text: String
    let filename: String
    @Environment(\.dismiss) private var dismiss
    @State private var failed = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Предпросмотр отчёта").font(.title2.weight(.semibold))
            Text("Отчёт очищен сетевым модулем. Проверьте содержимое перед сохранением; файл никуда не отправляется.")
                .font(.caption).foregroundStyle(.secondary)
            ScrollView { Text(text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(12) }
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
            if failed { Text("Файл не сохранён. Попробуйте другое место.").foregroundStyle(.orange) }
            HStack {
                Button("Закрыть") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Сохранить…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.json]
                    panel.nameFieldStringValue = filename
                    let finish: (NSApplication.ModalResponse) -> Void = { response in
                        guard response == .OK, let url = panel.url else { return }
                        do { try Data(text.utf8).write(to: url, options: .atomic); dismiss() }
                        catch { failed = true }
                    }
                    if let window = NSApp.keyWindow { panel.beginSheetModal(for: window, completionHandler: finish) }
                    else { panel.begin(completionHandler: finish) }
                }.keyboardShortcut(.defaultAction)
            }
        }.padding(24).frame(width: 600, height: 580)
    }
}
