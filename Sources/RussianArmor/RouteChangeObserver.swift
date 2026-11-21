import Darwin
import Foundation
import SystemConfiguration

struct RouteFingerprint: Equatable, Sendable {
    let value: String

    static func current() -> RouteFingerprint {
        var parts = [globalState("IPv4"), globalState("IPv6")]
        var pointer: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&pointer) == 0, let first = pointer {
            defer { freeifaddrs(first) }
            var addresses: [String] = []
            var cursor: UnsafeMutablePointer<ifaddrs>? = first
            while let item = cursor?.pointee {
                defer { cursor = item.ifa_next }
                guard let address = item.ifa_addr else { continue }
                let family = Int32(address.pointee.sa_family)
                guard family == AF_INET || family == AF_INET6 else { continue }
                let flags = Int32(item.ifa_flags)
                guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                guard getnameinfo(
                    address,
                    socklen_t(address.pointee.sa_len),
                    &host,
                    socklen_t(host.count),
                    nil,
                    0,
                    NI_NUMERICHOST
                ) == 0 else { continue }
                addresses.append("\(String(cString: item.ifa_name))=\(String(cString: host))")
            }
            parts.append(addresses.sorted().joined(separator: ","))
        }
        return RouteFingerprint(value: parts.joined(separator: "|"))
    }

    private static func globalState(_ family: String) -> String {
        let key = "State:/Network/Global/\(family)" as CFString
        guard let values = SCDynamicStoreCopyValue(nil, key) as? [String: Any] else {
            return "\(family):none"
        }
        let fields = ["PrimaryInterface", "PrimaryService", "Router"]
        return family + ":" + fields.map { field in
            "\(field)=\(values[field].map(String.init(describing:)) ?? "")"
        }.joined(separator: ",")
    }
}

struct RouteChangeFilter {
    private var previous: RouteFingerprint?

    init(initial: RouteFingerprint? = nil) {
        previous = initial
    }

    mutating func accepts(_ next: RouteFingerprint) -> Bool {
        defer { previous = next }
        guard let previous else { return false }
        return previous != next
    }
}

@MainActor
final class RouteChangeObserver {
    var onChange: (() -> Void)?

    private var descriptor: Int32 = -1
    private var source: DispatchSourceRead?
    private var filter = RouteChangeFilter()
    private let fingerprint: () -> RouteFingerprint

    init(fingerprint: @escaping () -> RouteFingerprint = RouteFingerprint.current) {
        self.fingerprint = fingerprint
    }

    var isMonitoring: Bool { descriptor >= 0 }

    func start() {
        stop()
        filter = RouteChangeFilter(initial: fingerprint())
        let fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)
        guard fd >= 0 else { return }
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        descriptor = fd
        let next = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        next.setEventHandler { [weak self] in self?.drainChanges() }
        next.setCancelHandler { Darwin.close(fd) }
        source = next
        next.resume()
    }

    func stop() {
        source?.cancel()
        source = nil
        descriptor = -1
    }

    private func drainChanges() {
        guard descriptor >= 0 else { return }
        var buffer = [UInt8](repeating: 0, count: 8_192)
        var routeChanged = false
        while true {
            let count = recv(descriptor, &buffer, buffer.count, MSG_DONTWAIT)
            guard count > 0 else { break }
            if Self.containsRouteChange(buffer.prefix(count)) { routeChanged = true }
        }
        let changed = filter.accepts(fingerprint())
        // Revoke permission immediately. Only the subsequent external requests
        // are debounced; repeated route messages must not postpone the pause.
        if changed || routeChanged { onChange?() }
    }

    // Routing socket messages begin with length, version and type. Treat
    // malformed notifications conservatively: they may represent a route change.
    nonisolated static func containsRouteChange(_ message: ArraySlice<UInt8>) -> Bool {
        let bytes = Array(message)
        guard bytes.count >= 4 else { return true }
        let length = Int(bytes[0]) | (Int(bytes[1]) << 8)
        guard length >= 4, length <= bytes.count else { return true }
        return [RTM_ADD, RTM_DELETE, RTM_CHANGE, RTM_REDIRECT].contains(Int32(bytes[3]))
    }

    deinit {
        source?.cancel()
    }
}
