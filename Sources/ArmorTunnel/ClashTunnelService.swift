import Foundation
import ServiceManagement

@objc public protocol ClashTunnelReading {
    func readTunnels(withReply reply: @escaping (Data?) -> Void)
}

public enum ClashTunnelService {
    public static let name = "app.russian-armor.clash-reader"
    public static var service: SMAppService { .daemon(plistName: name + ".plist") }
    public static var isEnabled: Bool { service.status == .enabled }

    /// Every observation needs a fresh response from the system bootstrap domain.
    /// Never carry an earlier owner across a timeout, crash or service restart.
    static func read() throws -> [VerifiedTunnel] {
        try read(using: NSXPCConnection(machServiceName: name, options: .privileged))
    }

    static func read(using connection: NSXPCConnection) throws -> [VerifiedTunnel] {
        connection.remoteObjectInterface = NSXPCInterface(with: ClashTunnelReading.self)
        let result = Reply()
        connection.interruptionHandler = { result.finish(nil) }
        connection.invalidationHandler = { result.finish(nil) }
        connection.resume()
        defer { connection.invalidate() }
        guard let reader = connection.remoteObjectProxyWithErrorHandler({ _ in result.finish(nil) }) as? ClashTunnelReading
        else { throw TunnelCheckError.readerUnavailable }
        reader.readTunnels { result.finish($0) }
        guard result.signal.wait(timeout: .now() + 3) == .success, let data = result.data, data.count <= 65536
        else { throw TunnelCheckError.readerUnavailable }
        guard let tunnels = try? JSONDecoder().decode([VerifiedTunnel].self, from: data) else { throw TunnelCheckError.readerUnavailable }
        return tunnels
    }

    private final class Reply: @unchecked Sendable {
        let signal = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var completed = false
        private(set) var data: Data?

        func finish(_ value: Data?) {
            lock.lock()
            defer { lock.unlock() }
            guard !completed else { return }
            completed = true
            data = value
            signal.signal()
        }
    }
}
