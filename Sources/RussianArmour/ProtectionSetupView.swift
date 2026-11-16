import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// A single import action installs the endpoint credential in Keychain and asks
/// macOS to enable the per-app extension. Router adapters supply the same format.
struct ProtectionSetupView: View {
    @ObservedObject var controller: ProtectionController
    @State private var isWorking = false
    @State private var errorMessage: String?
    @State private var confirmsRemoval = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(controller.status.title, systemImage: "shield.lefthalf.filled")
                .font(.headline)
            Text(controller.status.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            switch controller.status {
            case .configurationRequired:
                Button("Подключить защиту…", action: importConnection)
                    .disabled(isWorking)
            case .readyToInstall:
                Text("Подключение включится автоматически при запуске.")
                    .font(.caption)
                Button("Повторить подключение", action: enable)
                    .disabled(isWorking)
            case .failed:
                HStack {
                    Button("Повторить", action: enable)
                    Button("Другое подключение…", action: importConnection)
                }
                .disabled(isWorking)
                Button("Удалить подключение…") { confirmsRemoval = true }
                    .disabled(isWorking)
            case .channelEnabled:
                Button("Удалить защиту…") { confirmsRemoval = true }
                    .disabled(isWorking)
            case .approvalRequired:
                Text("Разрешение нужно только при первой установке.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            default:
                EmptyView()
            }
            if isWorking { ProgressView().controlSize(.small) }
            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .confirmationDialog("Удалить защиту Claude?", isPresented: $confirmsRemoval, titleVisibility: .visible) {
            Button("Удалить защиту", role: .destructive) { remove() }
        } message: {
            Text("Системный канал будет удалён. Claude сможет подключаться напрямую через обычную сеть.")
        }
    }

    private func enable() {
        isWorking = true
        errorMessage = nil
        Task { @MainActor in
            defer { isWorking = false }
            do { try await controller.installAndEnable() }
            catch { errorMessage = controller.status.detail }
        }
    }

    private func remove() {
        isWorking = true
        errorMessage = nil
        Task { @MainActor in
            defer { isWorking = false }
            do { try await controller.removeProtection() }
            catch { errorMessage = controller.status.detail }
        }
    }

    private func importConnection() {
        let panel = NSOpenPanel()
        panel.title = "Подключение Russian Armour"
        panel.message = "Выберите файл подключения Russian Armour."
        panel.allowedContentTypes = [.json]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        isWorking = true
        errorMessage = nil
        Task { @MainActor in
            defer { isWorking = false }
            do {
                let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
                guard values.isRegularFile == true, let size = values.fileSize, (1...16_384).contains(size) else {
                    throw CocoaError(.fileReadCorruptFile)
                }
                let imported = try JSONDecoder().decode(ConnectionImport.self, from: Data(contentsOf: url))
                guard imported.version == 1 else { throw CocoaError(.fileReadCorruptFile) }
                try await controller.configure(host: imported.host, port: imported.port, username: imported.username,
                                               password: imported.password,
                                               routerCertificateSHA256: imported.routerCertificateSHA256)
                try await controller.installAndEnable()
            } catch {
                // Raw decoder/OS errors can include file contents or credential data.
                errorMessage = "Не удалось подключить защиту. Проверьте файл подключения и разрешение macOS."
            }
        }
    }

    private struct ConnectionImport: Decodable {
        let version: Int
        let host: String
        let port: UInt16
        let username: String
        let password: String
        let routerCertificateSHA256: String
    }
}
