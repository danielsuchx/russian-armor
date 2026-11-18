import ArmorTunnel
import Darwin
import Foundation
import Security

final class Reader: NSObject, ClashTunnelReading, NSXPCListenerDelegate {
    private let queue = DispatchQueue(label: "app.russian-armor.clash-read")
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: ClashTunnelReading.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func readTunnels(withReply reply: @escaping (Data?) -> Void) {
        queue.async {
            do { reply(try JSONEncoder().encode(TunnelOwnershipReader.readPrivilegedProviders())) }
            catch { reply(nil) }
        }
    }
}

// Restrict the read-only endpoint to the exact GUI binaries in this installation.
// The distributed bundle is ad-hoc signed, so its signing identifier alone is insufficient.
func clientRequirement() -> String? {
    var length: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &length)
    var path = [CChar](repeating: 0, count: Int(length))
    guard _NSGetExecutablePath(&path, &length) == 0 else { return nil }
    let bundle = URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    var clauses: [String] = []
    for architecture in ["arm64", "x86_64"] {
        var code: SecStaticCode?
        let attributes = [kSecCodeAttributeArchitecture: architecture] as CFDictionary
        guard SecStaticCodeCreateWithPathAndAttributes(bundle as CFURL, [], attributes, &code) == errSecSuccess,
              let code else { continue }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
              let values = info as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == "app.russian-armor.desktop",
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else { continue }
        let hex = hash.map { String(format: "%02x", $0) }.joined()
        clauses.append("cdhash H\"\(hex)\"")
    }
    return clauses.isEmpty ? nil : clauses.joined(separator: " or ")
}

guard geteuid() == 0, getppid() == 1, let requirement = clientRequirement() else { exit(EXIT_FAILURE) }
let reader = Reader()
let listener = NSXPCListener(machServiceName: ClashTunnelService.name)
listener.setConnectionCodeSigningRequirement(requirement)
listener.delegate = reader
listener.resume()
dispatchMain()
