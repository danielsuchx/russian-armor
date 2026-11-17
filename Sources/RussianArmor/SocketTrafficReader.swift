import ArmorCore
import Darwin
import Foundation

enum TrafficReadError: Error, LocalizedError {
    case unavailable
    case noReadableProcesses
    case rootNotSupported

    var errorDescription: String? {
        switch self {
        case .unavailable: return "macOS не предоставила список процессов. Снимок недоступен."
        case .noReadableProcesses: return "Не удалось прочитать процессы текущего пользователя. Это не означает отсутствие соединений."
        case .rootNotSupported: return "Индексирование рассчитано на обычного пользователя. Не запускайте приложение через sudo."
        }
    }
}

/// Public libproc metadata APIs only: no packet capture, DNS lookup, process arguments,
/// socket reads, elevated privileges or changes to the observed sockets.
struct SocketTrafficReader {
    static let maximumProcesses = 512
    static let maximumDescriptors = 4096
    static let maximumDuration: TimeInterval = 1.5

    static func snapshot() async throws -> TrafficSnapshot {
        let work = Task.detached(priority: .utility) { try read() }
        return try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
    }

    static func read(identities: Set<TrafficProcess.ID>? = nil) throws -> TrafficSnapshot {
        let capturedAt = Date()
        let uid = getuid()
        guard uid != 0, geteuid() == uid else { throw TrafficReadError.rootNotSupported }
        let deadline = ProcessInfo.processInfo.systemUptime + maximumDuration
        var pids: [Int32]
        var truncated = false
        if let identities {
            // Targeted protection scans must not be crowded out by unrelated
            // processes hitting the optional all-user diagnostic scan's limit.
            pids = Array(Set(identities.map(\.pid))).sorted()
            truncated = pids.count > maximumProcesses
        } else {
            pids = [Int32](repeating: 0, count: maximumProcesses + 1)
            let bytes = pids.withUnsafeMutableBytes {
                proc_listpids(UInt32(PROC_UID_ONLY), uid, $0.baseAddress, Int32($0.count))
            }
            guard bytes > 0, Int(bytes) % MemoryLayout<Int32>.stride == 0 else { throw TrafficReadError.unavailable }
            let count = min(Int(bytes) / MemoryLayout<Int32>.stride, pids.count)
            truncated = count > maximumProcesses
            pids = Array(pids.prefix(count))
        }
        var rows: [TrafficConnection] = []
        var inspected = 0
        var inaccessible = 0
        var missedSockets = 0
        for pid in pids.filter({ $0 > 0 }).sorted().prefix(maximumProcesses) {
            try Task.checkCancellation()
            if ProcessInfo.processInfo.systemUptime >= deadline || rows.count >= TrafficSnapshot.capacity {
                truncated = true
                break
            }
            guard var before = processInfo(pid), belongsToUser(before, uid) else {
                inaccessible += 1
                continue
            }
            let process = TrafficProcess(
                id: .init(pid: pid, startSeconds: before.pbi_start_tvsec, startMicroseconds: before.pbi_start_tvusec),
                name: processName(&before, pid: pid)
            )
            if let identities, !identities.contains(process.id) {
                inaccessible += 1
                continue
            }
            var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: maximumDescriptors + 1)
            let fdBytes = descriptors.withUnsafeMutableBytes {
                proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count))
            }
            guard fdBytes >= 0, fdBytes != 0 || before.pbi_nfiles == 0 else {
                inaccessible += 1
                continue
            }
            let fdCount = min(max(0, Int(fdBytes)) / MemoryLayout<proc_fdinfo>.stride, descriptors.count)
            if fdCount > maximumDescriptors { truncated = true }
            var processRows: [TrafficConnection] = []
            for fd in descriptors.prefix(min(fdCount, maximumDescriptors)) where fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
                try Task.checkCancellation()
                if ProcessInfo.processInfo.systemUptime >= deadline || rows.count + processRows.count >= TrafficSnapshot.capacity {
                    truncated = true
                    break
                }
                var info = socket_fdinfo()
                let received = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info,
                                             Int32(MemoryLayout<socket_fdinfo>.size))
                guard received == MemoryLayout<socket_fdinfo>.size else {
                    missedSockets += 1
                    continue
                }
                if let row = decode(info, process: process, descriptor: fd.proc_fd) { processRows.append(row) }
            }
            // PID reuse, changed ownership/name and process exit can happen during a scan.
            // Discard this process's rows unless its identity and ownership still match.
            guard var after = processInfo(pid), belongsToUser(after, uid),
                  before.pbi_start_tvsec == after.pbi_start_tvsec,
                  before.pbi_start_tvusec == after.pbi_start_tvusec,
                  process.name == TrafficProcess(id: process.id, name: processName(&after, pid: pid)).name else {
                inaccessible += 1
                continue
            }
            inspected += 1
            rows.append(contentsOf: processRows)
        }
        try Task.checkCancellation()
        guard inspected > 0 || identities?.isEmpty == true else { throw TrafficReadError.noReadableProcesses }
        return TrafficSnapshot(connections: rows, capturedAt: capturedAt, inspectedProcesses: inspected, inaccessibleProcesses: inaccessible,
                               inaccessibleSockets: missedSockets, isTruncated: truncated)
    }

    static func belongsToUser(_ info: proc_bsdinfo, _ uid: uid_t) -> Bool {
        info.pbi_uid == uid && info.pbi_ruid == uid && info.pbi_svuid == uid
    }

    private static func processInfo(_ pid: Int32) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let received = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        return received == MemoryLayout<proc_bsdinfo>.size ? info : nil
    }

    private static func processName(_ info: inout proc_bsdinfo, pid: Int32) -> String {
        let name = withUnsafeBytes(of: &info.pbi_name) {
            String(bytes: $0.prefix(while: { $0 != 0 }), encoding: .utf8)
        }
        return name.flatMap { $0.isEmpty ? nil : $0 } ?? "PID \(pid)"
    }

    /// Kept separate so address families, port byte order and non-peer sockets
    /// can be validated using synthetic kernel structs, without observing live traffic.
    static func decode(_ info: socket_fdinfo, process: TrafficProcess, descriptor: Int32) -> TrafficConnection? {
        let socket = info.psi
        guard socket.soi_family == AF_INET || socket.soi_family == AF_INET6 else { return nil }
        let transport: TrafficTransport
        let inet: in_sockinfo
        let state: String
        if socket.soi_kind == SOCKINFO_TCP && socket.soi_protocol == IPPROTO_TCP && socket.soi_type == SOCK_STREAM {
            let tcp = socket.soi_proto.pri_tcp
            guard tcp.tcpsi_state != TSI_S_LISTEN, tcp.tcpsi_state != TSI_S_CLOSED else { return nil }
            transport = .tcp
            inet = tcp.tcpsi_ini
            state = tcpState(tcp.tcpsi_state)
        } else if socket.soi_kind == SOCKINFO_IN && socket.soi_protocol == IPPROTO_UDP && socket.soi_type == SOCK_DGRAM {
            transport = .udp
            inet = socket.soi_proto.pri_in
            state = "Задан peer"
        } else { return nil }
        let version: TrafficIPVersion
        let local: String?
        let remote: String?
        if Int(inet.insi_vflag) & Int(INI_IPV4) != 0 {
            version = .v4
            local = address(inet.insi_laddr.ina_46.i46a_addr4, family: AF_INET)
            remote = address(inet.insi_faddr.ina_46.i46a_addr4, family: AF_INET)
        } else if Int(inet.insi_vflag) & Int(INI_IPV6) != 0 {
            version = .v6
            local = address(inet.insi_laddr.ina_6, family: AF_INET6)
            remote = address(inet.insi_faddr.ina_6, family: AF_INET6)
        } else { return nil }
        let remotePort = UInt16(bigEndian: UInt16(truncatingIfNeeded: inet.insi_fport))
        guard let local, let remote, remote != "0.0.0.0", remote != "::", remotePort != 0 else { return nil }
        return TrafficConnection(process: process, socketGeneration: inet.insi_gencnt, descriptor: descriptor,
                                 transport: transport,
                                 local: .init(address: local, port: UInt16(bigEndian: UInt16(truncatingIfNeeded: inet.insi_lport)), version: version),
                                 remote: .init(address: remote, port: remotePort, version: version), state: state)
    }

    private static func address<T>(_ address: T, family: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = withUnsafeBytes(of: address) {
            inet_ntop(family, $0.baseAddress, &buffer, socklen_t(buffer.count))
        }
        guard result != nil else { return nil }
        return String(cString: buffer)
    }

    private static func tcpState(_ value: Int32) -> String {
        switch value {
        case TSI_S_SYN_SENT: return "SYN sent"
        case TSI_S_SYN_RECEIVED: return "SYN received"
        case TSI_S_ESTABLISHED: return "Установлено"
        case TSI_S__CLOSE_WAIT: return "Close wait"
        case TSI_S_FIN_WAIT_1, TSI_S_FIN_WAIT_2: return "Fin wait"
        case TSI_S_CLOSING: return "Закрывается"
        case TSI_S_LAST_ACK: return "Last ACK"
        case TSI_S_TIME_WAIT: return "Time wait"
        default: return "Состояние \(value)"
        }
    }
}
