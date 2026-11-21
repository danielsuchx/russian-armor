import ArmorIPC
import Darwin
import Foundation
import Security

enum NetworkEngineError: LocalizedError {
    case unavailable, invalidResponse, missingHelper, rejected(EngineValue), insecureDirectory
    var errorDescription: String? {
        switch self {
        case .unavailable: return "Сетевой модуль не отвечает. Доступ через шлюз не подтверждён."
        case .invalidResponse: return "Не удалось прочитать ответ сетевого модуля."
        case .missingHelper: return "Сетевой модуль отсутствует в этой сборке. Соберите полное приложение."
        case .insecureDirectory: return "Не удалось создать приватное подключение к сетевому модулю."
        case .rejected(let value):
            let text = value.optionalString ?? value["message"].optionalString ?? "Действие не выполнено."
            return EnginePrivacy.display(text)
        }
    }
}

struct NetworkEngineClient: Sendable {
    let socket: String
    let token: String

    func call(_ command: String, _ args: [String: EngineValue] = [:]) async throws -> EngineValue {
        let payload = EngineValue.object(["token": .string(token), "command": .string(command), "args": .object(args)])
        let request = try JSONEncoder().encode(payload)
        guard request.count < 1024 * 1024 else { throw NetworkEngineError.invalidResponse }
        let socket = socket
        let timeout: UInt32 = ["native_ping", "get_state", "get_startup_state"].contains(command) ? 3 : 120
        let data = try await Task.detached(priority: .userInitiated) {
            var response = [UInt8](repeating: 0, count: 8 * 1024 * 1024)
            var length = 0
            let code = request.withUnsafeBytes { bytes in
                ra_engine_exchange(socket, timeout, bytes.bindMemory(to: UInt8.self).baseAddress, request.count,
                                   &response, response.count, &length)
            }
            guard code == 0 else { throw NetworkEngineError.unavailable }
            return Data(response.prefix(length))
        }.value
        guard let envelope = try? JSONDecoder().decode(EngineValue.self, from: data) else {
            throw NetworkEngineError.invalidResponse
        }
        guard envelope["ok"].bool else { throw NetworkEngineError.rejected(envelope["error"]) }
        return envelope["value"]
    }

    static func sessionDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ra-network-\(getuid())", isDirectory: true)
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        }
        var metadata = stat()
        guard lstat(directory.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_uid == getuid(), metadata.st_mode & 0o077 == 0 else {
            throw NetworkEngineError.insecureDirectory
        }
        return directory
    }

    static func makeSession(in directory: URL) throws -> NetworkEngineClient {
        let path = directory.appendingPathComponent("session")
        var metadata = stat()
        if lstat(path.path, &metadata) == 0 {
            guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_uid == getuid(), metadata.st_mode & 0o077 == 0 else {
                throw NetworkEngineError.insecureDirectory
            }
            if let token = try? String(contentsOf: path, encoding: .utf8), validToken(token) {
                return .init(socket: directory.appendingPathComponent("engine.sock").path, token: token)
            }
            throw NetworkEngineError.insecureDirectory
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw NetworkEngineError.insecureDirectory
        }
        let token = bytes.map { String(format: "%02x", $0) }.joined()
        let temporary = directory.appendingPathComponent("session-\(UUID().uuidString)")
        let fd = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw NetworkEngineError.insecureDirectory }
        defer { try? FileManager.default.removeItem(at: temporary) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: Data(token.utf8))
        try handle.synchronize()
        try handle.close()
        guard Darwin.link(temporary.path, path.path) == 0 else { throw NetworkEngineError.insecureDirectory }
        return .init(socket: directory.appendingPathComponent("engine.sock").path, token: token)
    }

    static func validToken(_ token: String) -> Bool {
        token.utf8.count == 64 && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}
