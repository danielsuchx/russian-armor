import SwiftUI
import AppKit

let desktopID = "com.anthropic.claudefordesktop"
let fm = FileManager.default

func candidates() -> [URL] {
    let home = fm.homeDirectoryForCurrentUser
    let paths = [
        ".claude", ".claude.json", ".local/share/claude", ".local/bin/claude",
        "Library/Application Support/Claude", "Library/Application Support/Claude-3p",
        "Library/Caches/claude-cli-nodejs", "Library/Logs/Claude",
        "Library/Caches/\(desktopID)", "Library/Caches/\(desktopID).ShipIt",
        "Library/Preferences/\(desktopID).plist", "Library/WebKit/\(desktopID)",
        "Library/HTTPStorages/\(desktopID)", "Library/HTTPStorages/\(desktopID).binarycookies",
        "Library/Saved Application State/\(desktopID).savedState"
    ]
    let apps = [URL(fileURLWithPath: "/Applications/Claude.app"), home.appendingPathComponent("Applications/Claude.app")]
    return apps.filter { Bundle(url: $0)?.bundleIdentifier == desktopID } + paths.map { home.appendingPathComponent($0) }.filter {
        (try? fm.attributesOfItem(atPath: $0.path)) != nil
    }
}

struct RemovalView: View {
    @State private var files = candidates()
    @State private var selected = Set<URL>()
    @State private var report = ""
    @State private var confirm = false
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Удаление Claude").font(.largeTitle.bold())
            Text("Закройте Claude Desktop и завершите сеансы Claude Code. Отметьте файлы для переноса в Корзину.")
            List(files, id: \.self) { url in
                Toggle(isOn: Binding(get: { selected.contains(url) }, set: { value in
                    if value { selected.insert(url) } else { selected.remove(url) }
                })) {
                    VStack(alignment: .leading) {
                        Text(url.lastPathComponent).bold()
                        Text(url.path).font(.caption).foregroundStyle(.secondary)
                    }
                }.toggleStyle(.checkbox)
            }
            if files.isEmpty { Text("В проверенных папках объекты Claude не найдены.") }
            if !report.isEmpty { ScrollView { Text(report).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 85) }
            HStack {
                Button("Обновить") { files = candidates(); selected.formIntersection(files); report = "" }
                Button(selected.count == files.count && !files.isEmpty ? "Снять выбор" : "Выбрать все") {
                    selected = selected.count == files.count ? [] : Set(files)
                }.disabled(files.isEmpty)
                Spacer()
                Button("В Корзину (\(selected.count))") { confirm = true }.disabled(selected.isEmpty)
            }
        }.padding(22).frame(minWidth: 630, minHeight: 400).disabled(busy)
        .alert("Переместить выбранные объекты в Корзину?", isPresented: $confirm) {
            Button("Отмена", role: .cancel) {}
            Button("Переместить", role: .destructive) { removeSelected() }
        } message: {
            Text("Папки перемещаются целиком. В них могут храниться история сеансов, настройки MCP, плагины и рабочие файлы.")
        }
    }

    func removeSelected() {
        guard NSRunningApplication.runningApplications(withBundleIdentifier: desktopID).isEmpty else {
            report = "Claude Desktop открыт. Завершите приложение через ⌘Q и повторите."
            return
        }
        let requested = selected
        busy = true
        report = "Перенос в Корзину…"
        Task {
            let result = await Task.detached {
                let allowed = Set(candidates())
                var moved = 0
                var errors: [String] = []
                for url in requested.sorted(by: { $0.path < $1.path }) {
                    guard allowed.contains(url) else {
                        errors.append("\(url.path) — объект больше недоступен.")
                        continue
                    }
                    do {
                        try fm.trashItem(at: url, resultingItemURL: nil)
                        moved += 1
                    } catch {
                        errors.append("\(url.path) — \(error.localizedDescription)")
                    }
                }
                return (["Перемещено в Корзину: \(moved) из \(requested.count)."] + errors).joined(separator: "\n")
            }.value
            files = candidates()
            selected.formIntersection(files)
            report = result
            busy = false
        }
    }
}

@main
struct RemovalApp: App {
    var body: some Scene {
        Window("Удаление Claude", id: "main") { RemovalView() }.defaultSize(width: 760, height: 540)
    }
}
