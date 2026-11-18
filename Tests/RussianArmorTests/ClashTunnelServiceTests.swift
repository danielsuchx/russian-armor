@testable import ArmorTunnel
import Darwin
import Foundation
import XCTest

final class ClashTunnelServiceTests: XCTestCase {
    private final class Reader: NSObject, NSXPCListenerDelegate, ClashTunnelReading {
        let payload: Data?
        init(payload: Data?) { self.payload = payload }
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: ClashTunnelReading.self)
            connection.exportedObject = self
            connection.resume()
            return true
        }
        func readTunnels(withReply reply: @escaping (Data?) -> Void) { reply(payload) }
    }

    private func read(_ data: Data?) throws -> [VerifiedTunnel] {
        let listener = NSXPCListener.anonymous()
        let reader = Reader(payload: data)
        listener.delegate = reader
        listener.resume()
        defer { listener.invalidate() }
        return try withExtendedLifetime(reader) {
            try ClashTunnelService.read(using: NSXPCConnection(listenerEndpoint: listener.endpoint))
        }
    }

    func testXPCPreservesTunnelIdentityAndRejectsFailedReplies() throws {
        let tunnel = VerifiedTunnel(interface: "utun4", owner: .init(pid: 42, startSeconds: 88, startMicroseconds: 9),
                                    teamID: "JPH3Z7PPBB", signingID: "verge-mihomo", sourceAddresses: ["10.0.0.1"])
        XCTAssertEqual(try read(JSONEncoder().encode([tunnel])), [tunnel])
        XCTAssertThrowsError(try read(nil))
        XCTAssertThrowsError(try read(Data("incomplete".utf8)))
    }
}
