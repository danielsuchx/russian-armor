import AppKit
import ArmorCore
import SwiftUI
import UniformTypeIdentifiers

/// Bytes are prepared once, then previewed and saved unchanged. Background
/// checks may continue without silently changing the report being shared.
struct DiagnosticExport: Identifiable {
    let id = UUID()
    let report: DiagnosticReport
    let data: Data

    init(report: DiagnosticReport) throws {
        self.report = report
        data = try report.jsonData()
    }
}

struct DiagnosticSummaryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var export: DiagnosticExport?
    @State private var preparationFailed = false
    @State private var showsFindings = false

    var body: some View {
        SettingsCard(title: "Сводка проверок") {
            VStack(alignment: .leading, spacing: 14) {
                // Check freshness even if no model publisher has fired since
                // the last successful result. This timer performs no I/O.
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    let checks = model.diagnosticReport().checks
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(checks) { check in
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Image(systemName: check.status.symbol)
                                    .foregroundStyle(check.status == .attention ? Color.orange : Color.secondary)
                                    .frame(width: 18)
                                    .accessibilityHidden(true)
                                Text(check.id.title)
                                Spacer(minLength: 4)
                                Text(check.status.title).foregroundStyle(.secondary)
                                    .multilineTextAlignment(.trailing)
                            }
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                            .help(check.finding.detail)
                            .accessibilityElement(children: .combine)
                            .accessibilityIdentifier("diagnostic-check-\(check.id.rawValue)")
                        }
                        DisclosureGroup("Что означают результаты", isExpanded: $showsFindings) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text(DiagnosticReportPrivacy.limitation).foregroundStyle(.secondary)
                                ForEach(checks) { check in
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(check.id.title).fontWeight(.medium)
                                        Text(check.finding.detail).foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 6)
                        }
                    }
                }
                Divider()
                Button("Предпросмотр отчёта…") {
                    do {
                        export = try DiagnosticExport(report: model.diagnosticReport())
                        preparationFailed = false
                    } catch {
                        preparationFailed = true
                    }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("settings-diagnostic-report")
                if preparationFailed {
                    Text("Не удалось подготовить отчёт. Попробуйте ещё раз.").foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .sheet(item: $export) { DiagnosticReportPreview(export: $0) }
    }
}

struct DiagnosticReportPreview: View {
    let export: DiagnosticExport
    @Environment(\.dismiss) private var dismiss
    @State private var saving = false
    @State private var saveFailed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Диагностический отчёт").font(.title2.weight(.semibold))
            Text("Снимок: \(export.report.createdAt.formatted(date: .abbreviated, time: .standard)). При сохранении содержимое не изменится.")
                .font(AppTypography.description).foregroundStyle(.secondary)
            Text(DiagnosticReportPrivacy.contents)
                .font(AppTypography.description).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                Text(String(decoding: export.data, as: UTF8.self))
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("diagnostic-report-preview")
            Text("Файл сохраняется только на вашем Mac. Russian Armor никуда его не отправляет.")
                .font(.caption).foregroundStyle(.secondary)
            if saveFailed {
                Text("Не удалось сохранить файл. Выберите другое место или повторите попытку.")
                    .font(AppTypography.description).foregroundStyle(.orange)
            }
            HStack {
                Button("Закрыть") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Сохранить JSON…", action: save)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("diagnostic-report-save")
            }
            .disabled(saving)
        }
        .padding(24)
        .frame(width: 600, height: 580)
    }

    private func save() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "Russian-Armor-diagnostics.json"
        panel.canCreateDirectories = true
        saving = true
        saveFailed = false
        let completion: (NSApplication.ModalResponse) -> Void = { response in
            saving = false
            guard response == .OK, let url = panel.url else { return }
            do {
                try export.data.write(to: url, options: .atomic)
                dismiss()
            } catch {
                // NSError descriptions can contain the user's destination path.
                saveFailed = true
            }
        }
        if let window = NSApp.keyWindow {
            panel.beginSheetModal(for: window, completionHandler: completion)
        } else {
            panel.begin(completionHandler: completion)
        }
    }
}
