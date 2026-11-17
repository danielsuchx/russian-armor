import Foundation

public enum TrafficTransport: String, Sendable { case tcp = "TCP", udp = "UDP" }
public enum TrafficIPVersion: String, Sendable { case v4 = "IPv4", v6 = "IPv6" }

public struct TrafficEndpoint: Hashable, Sendable {
    public let address: String
    public let port: UInt16
    public let version: TrafficIPVersion

    public init(address: String, port: UInt16, version: TrafficIPVersion) {
        self.address = address
        self.port = port
        self.version = version
    }

    public var title: String { version == .v6 ? "[\(address)]:\(port)" : "\(address):\(port)" }
    public var isLoopback: Bool {
        address.hasPrefix("127.") || address == "::1" || address.hasPrefix("::ffff:127.")
    }
}

public struct TrafficProcess: Hashable, Sendable {
    public struct ID: Hashable, Sendable {
        public let pid: Int32
        public let startSeconds: UInt64
        public let startMicroseconds: UInt64
        public init(pid: Int32, startSeconds: UInt64, startMicroseconds: UInt64) {
            self.pid = pid
            self.startSeconds = startSeconds
            self.startMicroseconds = startMicroseconds
        }
    }
    public let id: ID
    public let name: String
    public init(id: ID, name: String) {
        self.id = id
        let safeName = name.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0) && $0.properties.generalCategory != .format
        }
        self.name = String(String.UnicodeScalarView(safeName)).prefix(80).description
    }
}

/// Socket metadata only. Deliberately not Codable: endpoint data is never persisted.
public struct TrafficConnection: Identifiable, Equatable, Sendable {
    public struct ID: Hashable, Sendable {
        let process: TrafficProcess.ID
        let generation: UInt64
        let descriptorFallback: Int32
        let transport: TrafficTransport
        let local: TrafficEndpoint
        let remote: TrafficEndpoint
    }
    public let process: TrafficProcess
    public let socketGeneration: UInt64
    public let descriptor: Int32
    public let transport: TrafficTransport
    public let local: TrafficEndpoint
    public let remote: TrafficEndpoint
    public let state: String
    public var id: ID {
        ID(process: process.id, generation: socketGeneration,
           descriptorFallback: socketGeneration == 0 ? descriptor : -1,
           transport: transport, local: local, remote: remote)
    }

    public init(process: TrafficProcess, socketGeneration: UInt64, descriptor: Int32,
                transport: TrafficTransport, local: TrafficEndpoint, remote: TrafficEndpoint, state: String) {
        self.process = process
        self.socketGeneration = socketGeneration
        self.descriptor = descriptor
        self.transport = transport
        self.local = local
        self.remote = remote
        self.state = state
    }
}

public struct TrafficSnapshot: Equatable, Sendable {
    public static let capacity = 1000
    public let connections: [TrafficConnection]
    public let capturedAt: Date
    public let inspectedProcesses: Int
    public let inaccessibleProcesses: Int
    public let inaccessibleSockets: Int
    public let isTruncated: Bool
    public var isPartial: Bool { isTruncated || inaccessibleProcesses > 0 || inaccessibleSockets > 0 }

    public init(connections: [TrafficConnection], capturedAt: Date = Date(), inspectedProcesses: Int = 0,
                inaccessibleProcesses: Int = 0, inaccessibleSockets: Int = 0, isTruncated: Bool = false) {
        var seen = Set<TrafficConnection.ID>()
        let unique = connections.filter { seen.insert($0.id).inserted }
        self.connections = Array(unique.prefix(Self.capacity)).sorted {
            if $0.process.name != $1.process.name { return $0.process.name < $1.process.name }
            if $0.process.id.pid != $1.process.id.pid { return $0.process.id.pid < $1.process.id.pid }
            if $0.remote.title != $1.remote.title { return $0.remote.title < $1.remote.title }
            return $0.local.title < $1.local.title
        }
        self.capturedAt = capturedAt
        self.inspectedProcesses = inspectedProcesses
        self.inaccessibleProcesses = inaccessibleProcesses
        self.inaccessibleSockets = inaccessibleSockets
        self.isTruncated = isTruncated || unique.count > Self.capacity
    }
}
