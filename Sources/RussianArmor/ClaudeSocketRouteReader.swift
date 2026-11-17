import ArmorCore
import Darwin
import Foundation

/// Local kernel metadata only: no probes to Claude, no DNS, no packet capture.
/// RTM_GET is an unscoped routing-table lookup, NOT a read of a socket's actual
/// forwarding decision (per-app policies and proxy hops can differ).
enum ClaudeSocketRouteReader {
    static func snapshot(identities: Set<TrafficProcess.ID>) async throws -> ClaudeRouteSnapshot {
        let task = Task.detached(priority: .utility) { try read(identities: identities) }
        return try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
    }

    static func read(identities: Set<TrafficProcess.ID>) throws -> ClaudeRouteSnapshot {
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        let sockets = try SocketTrafficReader.read(identities: identities)
        let sources = interfaceAddresses()
        var cache: [TrafficEndpoint: String] = [:]
        var attempted = Set<TrafficEndpoint>()
        var routes: [ClaudeConnectionRoute] = []
        var partial = sockets.isPartial
        for connection in sockets.connections {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { partial = true; break }
            // The port does not change a routing-table lookup.
            let peer = TrafficEndpoint(address: connection.remote.address, port: 0, version: connection.remote.version)
            if attempted.insert(peer).inserted {
                guard attempted.count <= 64 else { partial = true; break }
                cache[peer] = SystemRouteLookup.interface(to: peer)
            }
            routes.append(ClaudeConnectionRoute(
                connection: connection,
                sourceInterfaces: sources[canonical(connection.local.address)] ?? [],
                routeInterface: cache[peer]
            ))
        }
        try Task.checkCancellation()
        return ClaudeRouteSnapshot(routes: routes, capturedAt: sockets.capturedAt, isPartial: partial)
    }

    private static func interfaceAddresses() -> [String: [String]] {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return [:] }
        defer { freeifaddrs(first) }
        var result: [String: [String]] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor?.pointee {
            defer { cursor = entry.ifa_next }
            guard let address = entry.ifa_addr,
                  [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)),
                  Int32(entry.ifa_flags) & IFF_UP != 0 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            result[canonical(String(cString: host)), default: []].append(String(cString: entry.ifa_name))
        }
        return result
    }

    private static func canonical(_ address: String) -> String {
        String(address.split(separator: "%", maxSplits: 1)[0]).lowercased()
    }
}

enum SystemRouteLookup {
    /// Bounded synchronous kernel request, used only from the utility worker.
    static func interface(to endpoint: TrafficEndpoint) -> String? {
        let fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { return nil }
        var destination: [UInt8]
        if endpoint.version == .v4 {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            guard inet_pton(AF_INET, endpoint.address, &address.sin_addr) == 1 else { return nil }
            destination = withUnsafeBytes(of: &address) { Array($0) }
        } else {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            guard inet_pton(AF_INET6, endpoint.address, &address.sin6_addr) == 1 else { return nil }
            destination = withUnsafeBytes(of: &address) { Array($0) }
        }
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + destination.count)
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_addrs = RTA_DST
        header.rtm_pid = getpid()
        header.rtm_seq = 1
        var request = withUnsafeBytes(of: &header) { Array($0) }
        request.append(contentsOf: destination)
        guard request.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, $0.count) }) == request.count else { return nil }
        let deadline = ProcessInfo.processInfo.systemUptime + 0.05
        var bytes = [UInt8](repeating: 0, count: 16_384)
        while ProcessInfo.processInfo.systemUptime < deadline, !Task.isCancelled {
            var event = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let milliseconds = Int32(max(1, (deadline - ProcessInfo.processInfo.systemUptime) * 1000))
            guard poll(&event, 1, milliseconds) > 0 else { return nil }
            let received = recv(fd, &bytes, bytes.count, MSG_DONTWAIT)
            guard received >= MemoryLayout<rt_msghdr>.size else { continue }
            if let index = responseInterfaceIndex(Array(bytes.prefix(received)), pid: header.rtm_pid, sequence: header.rtm_seq) {
                var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
                guard if_indextoname(UInt32(index), &name) != nil else { return nil }
                return String(cString: name)
            }
        }
        return nil
    }

    static func responseInterfaceIndex(_ bytes: [UInt8], pid: Int32, sequence: Int32) -> UInt16? {
        guard bytes.count >= MemoryLayout<rt_msghdr>.size else { return nil }
        var header = rt_msghdr()
        withUnsafeMutableBytes(of: &header) { $0.copyBytes(from: bytes.prefix($0.count)) }
        guard header.rtm_version == RTM_VERSION, header.rtm_type == RTM_GET,
              header.rtm_pid == pid, header.rtm_seq == sequence,
              Int(header.rtm_msglen) >= MemoryLayout<rt_msghdr>.size,
              Int(header.rtm_msglen) <= bytes.count,
              header.rtm_errno == 0, header.rtm_index != 0,
              header.rtm_flags & RTF_UP != 0,
              header.rtm_flags & (RTF_REJECT | RTF_BLACKHOLE) == 0 else { return nil }
        return header.rtm_index
    }
}
