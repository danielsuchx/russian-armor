import AppKit
import Combine
import SwiftUI

struct NetworkInterceptionView: View {
    @ObservedObject var engine: NetworkEngineStore
    var openGuide: () -> Void
    @State private var confirmsAllow = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(engine.pendingAlert["is_simulation"].bool ? "Тест сетевой блокировки" : "Передача данных остановлена", systemImage: "shield.slash")
                .font(.title3.weight(.semibold))
            if let reason = engine.pendingAlert["gate_reason"].optionalString {
                Text(engine.display(reason)).fixedSize(horizontal: false, vertical: true)
            }
            let change = engine.pendingAlert["network_change"]
            if case .object = change {
                HStack(alignment: .top, spacing: 14) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Было").font(.caption).foregroundStyle(.secondary)
                        Text(change["old_country"].optionalString ?? "Неизвестно")
                        Text(engine.display(change["old_ip"].optionalString ?? "Нет данных")).font(.caption.monospaced())
                    }
                    Image(systemName: "arrow.right").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Стало").font(.caption).foregroundStyle(.secondary)
                        Text(change["new_country"].optionalString ?? "Неизвестно")
                        Text(engine.display(change["new_ip"].optionalString ?? "Нет данных")).font(.caption.monospaced())
                    }
                }
            }
            if engine.pendingAlert["phase"].string == "detecting" {
                HStack { ProgressView().controlSize(.small); Text("Проверки ещё выполняются…").font(.caption) }
            }
            if let error = engine.error { Text(error).font(.caption).foregroundStyle(.orange) }
            Text("Разрешение сохранит исключение для сервиса и выходного IP. Прежние исключения можно удалить в настройках шлюза.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Оставить на паузе до смены сети") { engine.resolveAlert("blockUntilNetworkChange") }
            HStack {
                Button("Открыть памятку") { engine.resolveAlert("openGuideAndBlock"); openGuide() }
                Spacer()
                Button("Разрешить этот выход…") { confirmsAllow = true }
                    .disabled(engine.pendingAlert["phase"].string != "ready" || engine.pause["manual_killswitch"].bool)
            }
        }
        .font(AppTypography.description)
        .padding(22).frame(width: 440)
        .fixedSize(horizontal: false, vertical: true)
        .disabled(engine.busy.contains("resolve_interception"))
        .alert("Сохранить исключение для этого выхода?", isPresented: $confirmsAllow) {
            Button("Отмена", role: .cancel) {}
            Button("Разрешить") { engine.resolveAlert("allowSession") }
        } message: { Text("Сервис сможет использовать этот выход согласно исключению. Остальные правила защиты остаются в силе.") }
    }
}

@MainActor
final class NetworkInterceptionController {
    private var window: NSPanel?
    private var subscription: AnyCancellable?
    private let engine: NetworkEngineStore
    private let openGuide: () -> Void
    init(engine: NetworkEngineStore, openGuide: @escaping () -> Void) {
        self.engine = engine; self.openGuide = openGuide
        subscription = engine.$pendingAlert.receive(on: RunLoop.main).sink { [weak self] alert in self?.update(alert) }
    }
    private func update(_ alert: EngineValue) {
        guard alert["id"].optionalString != nil else {
            window?.orderOut(nil)
            window?.contentView = nil
            window = nil
            return
        }
        if engine.state["interception_behavior"].string == "auto_lock_silent" && !alert["is_simulation"].bool { return }
        if window == nil {
            let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .nonactivatingPanel], backing: .buffered, defer: false)
            panel.title = "Russian Armor"
            panel.isReleasedWhenClosed = false; panel.hidesOnDeactivate = false; panel.level = .floating
            panel.contentView = NSHostingView(rootView: NetworkInterceptionView(engine: engine, openGuide: openGuide))
            window = panel
        }
        guard let window, let screen = NSScreen.main else { return }
        let size = window.contentView?.fittingSize ?? NSSize(width: 440, height: 400)
        window.setContentSize(size)
        let frame = screen.visibleFrame
        let center = engine.state["popup_position"].string == "top_center"
        window.setFrameOrigin(NSPoint(x: center ? frame.midX - window.frame.width / 2 : frame.maxX - window.frame.width - 18,
                                      y: frame.maxY - window.frame.height - 18))
        window.orderFrontRegardless()
    }
}
