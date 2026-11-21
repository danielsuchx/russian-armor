import AppKit
import Combine
import SwiftUI

struct StatusPanelMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .popover
        view.blendingMode = .behindWindow
        view.state = .active
        view.appearance = NSAppearance(named: .darkAqua)
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {}
}

private final class StatusPanelWindow: NSPanel {
    var onEscape: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func cancelOperation(_ sender: Any?) { onEscape?() }
}

private final class StatusPanelHostingView: NSHostingView<AnyView> {
    var onLayout: ((CGFloat) -> Void)?
    private var isReportingLayout = false

    override func layout() {
        super.layout()
        guard !isReportingLayout else { return }
        isReportingLayout = true
        defer { isReportingLayout = false }
        onLayout?(fittingSize.height)
    }
}

@MainActor
final class StatusPanelController: NSObject {
    let window: NSPanel
    let presentation: StatusPanelPresentation
    private var localMonitor: Any?
    private var globalMonitor: Any?
    private weak var anchorButton: NSView?
    private let hostingView: StatusPanelHostingView
    private let contentView = NSView()
    private let scrollView = NSScrollView()
    private var placement: (anchor: NSRect, visibleFrame: NSRect)?
    private var modelSubscription: AnyCancellable?
    private let makeContent: () -> StatusPanelView
    private var layoutQueued = false

    init(model: AppModel, perform: @escaping (StatusPanelAction) -> Void) {
        let presentation = StatusPanelPresentation()
        self.presentation = presentation
        makeContent = { StatusPanelView(model: model, presentation: presentation, perform: perform) }
        // An ordered-out NSHostingView still observes its model and lays out.
        // Mount the live view only while the panel is open.
        hostingView = StatusPanelHostingView(rootView: AnyView(EmptyView()))
        let panel = StatusPanelWindow(
            contentRect: NSRect(x: 0, y: 0, width: StatusPanelLayout.width, height: 1),
            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false
        )
        window = panel
        super.init()
        panel.isReleasedWhenClosed = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.isExcludedFromWindowsMenu = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.animationBehavior = .none
        panel.appearance = NSAppearance(named: .darkAqua)
        panel.title = "Russian Armor"
        // The controller alone sizes the window. Normal content is not inside a
        // scroll view: DisclosureGroup must not scroll it before the window grows.
        hostingView.sizingOptions = [.intrinsicContentSize]
        hostingView.autoresizingMask = []
        hostingView.setFrameSize(NSSize(width: StatusPanelLayout.width, height: 1))
        scrollView.drawsBackground = false
        scrollView.contentView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.scrollerStyle = .overlay
        contentView.wantsLayer = true
        contentView.layer?.cornerRadius = StatusPanelLayout.cornerRadius
        contentView.layer?.masksToBounds = true
        contentView.addSubview(hostingView)
        panel.contentView = contentView
        // Resize in the hosting view's layout pass, before that layout is drawn.
        // Dispatching a measured height to the next run-loop turn exposes one
        // frame with new content centered inside the old document bounds.
        hostingView.onLayout = { [weak self] height in self?.resizeToFit(height: height) }
        panel.onEscape = { [weak self] in self?.close() }
        modelSubscription = model.objectWillChange.merge(with: presentation.objectWillChange).sink { [weak self] _ in
            // NSScrollView can preserve the document frame after its SwiftUI
            // content shrinks. Re-measure after the published change commits.
            guard let self, self.window.isVisible, !self.layoutQueued else { return }
            self.layoutQueued = true
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.layoutQueued = false
                guard self.window.isVisible else { return }
                self.hostingView.invalidateIntrinsicContentSize()
                self.hostingView.needsLayout = true
                self.hostingView.layoutSubtreeIfNeeded()
            }
        }
    }

    deinit {
        if let localMonitor { NSEvent.removeMonitor(localMonitor) }
        if let globalMonitor { NSEvent.removeMonitor(globalMonitor) }
    }

    /// Keep the content-sized surface on the status item's own display.
    static func frame(anchor: NSRect, visibleFrame: NSRect, contentHeight: CGFloat) -> NSRect {
        let top = min(anchor.minY - 4, visibleFrame.maxY)
        let availableHeight = max(1, min(visibleFrame.height - 12, top - visibleFrame.minY - 6))
        let size = NSSize(width: StatusPanelLayout.width,
                          height: min(ceil(contentHeight), availableHeight))
        let x = min(max(anchor.maxX - size.width, visibleFrame.minX + 6),
                    visibleFrame.maxX - size.width - 6)
        return NSRect(x: x, y: top - size.height, width: size.width, height: size.height)
    }

    static func shouldPinTop(previousDocumentHeight: CGFloat, viewportHeight: CGFloat,
                             scrollOrigin: CGFloat, topOrigin: CGFloat) -> Bool {
        previousDocumentHeight <= viewportHeight + 1 || abs(scrollOrigin - topOrigin) <= 1
    }

    private func resizeToFit(height: CGFloat) {
        guard height.isFinite, height > 0, let placement else { return }
        let frame = Self.frame(anchor: placement.anchor, visibleFrame: placement.visibleFrame,
                               contentHeight: height)
        let documentSize = NSSize(width: StatusPanelLayout.width, height: ceil(height))
        guard window.frame != frame || hostingView.frame.size != documentSize else { return }
        let wasScrolling = hostingView.enclosingScrollView != nil
        let previousDocumentHeight = hostingView.frame.height
        let topOrigin = hostingView.isFlipped ? hostingView.bounds.minY
            : max(hostingView.bounds.minY, hostingView.bounds.maxY - scrollView.contentSize.height)
        let shouldPinTop = !wasScrolling || Self.shouldPinTop(
            previousDocumentHeight: previousDocumentHeight,
            viewportHeight: scrollView.contentSize.height,
            scrollOrigin: scrollView.contentView.bounds.minY, topOrigin: topOrigin)
        // Do not present the new document inside the old window (or vice versa).
        // AppKit's content coordinates are bottom-based, so that intermediate
        // frame visibly shifts the whole SwiftUI surface during a disclosure.
        if window.isVisible { window.disableScreenUpdatesUntilFlush() }
        window.setFrame(frame, display: false, animate: false)
        let needsScrolling = ceil(height) > frame.height
        if needsScrolling {
            if !wasScrolling {
                hostingView.removeFromSuperview()
                contentView.addSubview(scrollView)
                scrollView.documentView = hostingView
            }
            scrollView.frame = NSRect(origin: .zero, size: frame.size)
        } else {
            if wasScrolling {
                scrollView.documentView = nil
                scrollView.removeFromSuperview()
                contentView.addSubview(hostingView)
            }
            hostingView.setFrameOrigin(.zero)
        }
        hostingView.setFrameSize(documentSize)
        contentView.layoutSubtreeIfNeeded()
        if needsScrolling && shouldPinTop { pinContentToTop() }
    }

    private func pinContentToTop() {
        guard hostingView.enclosingScrollView === scrollView,
              let documentView = scrollView.documentView else { return }
        scrollView.layoutSubtreeIfNeeded()
        let y = documentView.isFlipped
            ? documentView.bounds.minY
            : max(documentView.bounds.minY,
                  documentView.bounds.maxY - scrollView.contentView.bounds.height)
        scrollView.contentView.scroll(to: NSPoint(x: documentView.bounds.minX, y: y))
        scrollView.reflectScrolledClipView(scrollView.contentView)
    }

    func toggle(relativeTo button: NSView) {
        if window.isVisible {
            close()
        } else if let buttonWindow = button.window, let screen = buttonWindow.screen {
            anchorButton = button
            let anchor = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
            show(anchor: anchor, visibleFrame: screen.visibleFrame)
        }
    }

    func show(anchor: NSRect, visibleFrame: NSRect) {
        removeMonitors()
        placement = (anchor, visibleFrame)
        hostingView.rootView = AnyView(makeContent())
        resizeToFit(height: hostingView.fittingSize.height)
        window.makeKeyAndOrderFront(nil)
        // Menu-bar tracking can briefly take key focus from a nonactivating panel.
        // Dismiss on an actual app/Space switch or outside click.
        let workspace = NSWorkspace.shared.notificationCenter
        workspace.addObserver(self, selector: #selector(workspaceDidChange), name: NSWorkspace.activeSpaceDidChangeNotification, object: nil)
        workspace.addObserver(self, selector: #selector(workspaceDidChange), name: NSWorkspace.didActivateApplicationNotification, object: nil)
        globalMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            self?.handleGlobalMouseDown(at: NSEvent.mouseLocation)
        }
        localMonitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown, .keyDown]) { [weak self] event in
            guard let self else { return event }
            if event.type == .keyDown {
                if event.keyCode == 53 {
                    self.close()
                    return nil
                }
                return event
            }
            if event.window === self.window { return event }
            if let button = self.anchorButton, event.window === button.window,
               button.bounds.contains(button.convert(event.locationInWindow, from: nil)) { return event }
            self.close()
            return event
        }
    }

    func handleGlobalMouseDown(at screenPoint: NSPoint) {
        // Menu-bar events may arrive through the global monitor. The button's
        // own action must toggle the panel, not close it here and reopen it.
        if let button = anchorButton, let buttonWindow = button.window {
            let anchor = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
            if anchor.contains(screenPoint) { return }
        }
        close()
    }

    func close() {
        window.orderOut(nil)
        hostingView.rootView = AnyView(EmptyView())
        removeMonitors()
    }

    @objc private func workspaceDidChange(_ notification: Notification) {
        if let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
           app.processIdentifier == ProcessInfo.processInfo.processIdentifier { return }
        close()
    }

    private func removeMonitors() {
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        if let localMonitor { NSEvent.removeMonitor(localMonitor) }
        if let globalMonitor { NSEvent.removeMonitor(globalMonitor) }
        localMonitor = nil
        globalMonitor = nil
    }
}
