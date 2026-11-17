import ArmorCore
import Darwin
import Foundation
import SwiftUI

struct FirewallStatusPresentation: Equatable {
    let title: String
    let detail: String
    let verified: Bool

    init(status: FirewallStatus?, now: Date = Date()) {
        guard let status, status.isFresh(at: now) else {
            title = "Сетевая защита не подтверждена"
            detail = status == nil ? "Служба не обнаружена или её статус недоступен. Пауза Claude — отдельная защита, не сетевой kill switch."
                : "Нет свежего ответа службы. Старый статус не подтверждает текущую блокировку."
            verified = false
            return
        }
        switch status.state {
        case .disabled: title = "Сетевой kill switch выключен"
        case .blocked: title = "Прямой выход заблокирован"
        case .recovering: title = "Сеть заблокирована · проверка VPN"
        case .protected: title = "Весь Mac · только проверенный туннель"
        case .broken: title = "Ошибка сетевой защиты"
        }
        detail = status.detail
        verified = [.blocked, .recovering, .protected].contains(status.state)
    }
}

enum FirewallStatusReader {
    static let path = "/Library/Application Support/Russian Armor Firewall/status.json"
    static func read() -> FirewallStatus? {
        // A non-root GUI never writes service files or controls a privileged shell.
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
        var current = ""
        for part in directory.split(separator: "/") {
            current += "/" + part
            var info = stat()
            guard lstat(current, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == 0, info.st_mode & 0o022 == 0 else { return nil }
        }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
              info.st_uid == 0, info.st_mode & 0o022 == 0, info.st_size > 0, info.st_size <= 8192 else { return nil }
        var data = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
        let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        guard count == info.st_size else { return nil }
        return try? JSONDecoder().decode(FirewallStatus.self, from: Data(data.prefix(count)))
    }
}

struct FirewallSettingsView: View {
    @State private var presentation = FirewallStatusPresentation(status: nil)
    var body: some View {
        GroupBox("Сетевой kill switch · весь Mac") {
            VStack(alignment: .leading, spacing: 8) {
                Label(presentation.title, systemImage: presentation.verified ? "network.badge.shield.half.filled" : "exclamationmark.shield")
                    .font(.headline)
                Text(presentation.detail).font(.callout)
                Text("Экспериментальный режим: root-служба и pf, только VPN на этом Mac. Влияет на все программы. Установка и включение — отдельные команды администратора; приложение не включает их автоматически.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Политика службы хранится отдельно от правил Claude. При выходе из окна служба остаётся работать. Перед установкой прочитайте docs/kill-switch.md; проверка в изолированной macOS VM ещё обязательна.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
        .task {
            while !Task.isCancelled {
                presentation = FirewallStatusPresentation(status: FirewallStatusReader.read())
                do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { return }
            }
        }
    }
}
