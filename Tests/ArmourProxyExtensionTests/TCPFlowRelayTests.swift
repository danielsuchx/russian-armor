import Foundation
import XCTest
@testable import ArmourProxyExtension

final class TCPFlowRelayTests: XCTestCase {
    private final class Source: TCPProxySourceFlow {
        var opens = 0
        var reads = 0
        var writes: [Data] = []
        var readCloses: [NSError?] = []
        var writeCloses: [NSError?] = []
        var openCompletion: ((Error?) -> Void)?
        var readCompletion: ((Data?, Error?) -> Void)?
        var writeCompletion: ((Error?) -> Void)?

        func open(completion: @escaping (Error?) -> Void) { opens += 1; openCompletion = completion }
        func read(completion: @escaping (Data?, Error?) -> Void) { reads += 1; readCompletion = completion }
        func write(_ data: Data, completion: @escaping (Error?) -> Void) { writes.append(data); writeCompletion = completion }
        func closeRead(_ error: NSError?) { readCloses.append(error) }
        func closeWrite(_ error: NSError?) { writeCloses.append(error) }

        func completeOpen(_ error: Error? = nil) { let callback = openCompletion; openCompletion = nil; callback?(error) }
        func completeRead(_ data: Data?, error: Error? = nil) { let callback = readCompletion; readCompletion = nil; callback?(data, error) }
        func completeWrite(_ error: Error? = nil) { let callback = writeCompletion; writeCompletion = nil; callback?(error) }
    }

    private final class Transport: AuthenticatedRouterTransport {
        var onFailure: ((Error) -> Void)?
        var starts = 0
        var sends: [Data] = []
        var receiveLimits: [Int] = []
        var finishes = 0
        var cancels = 0
        var startCompletion: ((Error?) -> Void)?
        var sendCompletion: ((Error?) -> Void)?
        var finishCompletion: ((Error?) -> Void)?
        var receiveCompletion: ((Data?, Bool, Error?) -> Void)?

        func start(completion: @escaping (Error?) -> Void) { starts += 1; startCompletion = completion }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { sends.append(data); sendCompletion = completion }
        func finishSending(completion: @escaping (Error?) -> Void) { finishes += 1; finishCompletion = completion }
        func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            receiveLimits.append(maximumLength); receiveCompletion = completion
        }
        func cancel() { cancels += 1 }
        func completeStart(_ error: Error? = nil) { let callback = startCompletion; startCompletion = nil; callback?(error) }
        func completeSend(_ error: Error? = nil) { let callback = sendCompletion; sendCompletion = nil; callback?(error) }
        func completeFinish(_ error: Error? = nil) { let callback = finishCompletion; finishCompletion = nil; callback?(error) }
        func completeReceive(_ data: Data?, complete: Bool = false, error: Error? = nil) {
            let callback = receiveCompletion; receiveCompletion = nil; callback?(data, complete, error)
        }
    }

    private final class Harness {
        let queue = DispatchQueue(label: "TCPFlowRelayTests.\(UUID())")
        let source = Source()
        let transport = Transport()
        private(set) var finishes = 0
        lazy var relay = TCPFlowRelay(flow: source, transport: transport, queue: queue) { [weak self] in self?.finishes += 1 }

        func start() { queue.sync { relay.start() } }
        func drain() { queue.sync {} }
        func authenticateAndOpen() {
            start()
            queue.sync { transport.completeStart() }
            queue.sync { source.completeOpen() }
            drain()
        }
    }

    func testSourceIsNeverOpenedOrReadBeforeAuthenticatedRouterHandshake() {
        let h = Harness()
        h.start()
        h.queue.sync {
            XCTAssertEqual(h.transport.starts, 1)
            XCTAssertEqual(h.source.opens, 0)
            XCTAssertEqual(h.source.reads, 0)
            XCTAssertTrue(h.transport.receiveLimits.isEmpty)
            XCTAssertTrue(h.transport.sends.isEmpty)
        }
        h.queue.sync { h.transport.completeStart(RouterProxyError.refused) }
        h.queue.sync {
            XCTAssertEqual(h.source.opens, 0)
            XCTAssertEqual(h.source.reads, 0)
            XCTAssertEqual(h.source.readCloses.count, 1)
            XCTAssertEqual(h.source.writeCloses.count, 1)
            XCTAssertNotNil(h.source.readCloses.first!)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testFlowOpenFailureClosesAuthenticatedTransportWithoutReadingApplicationData() {
        let h = Harness()
        h.start()
        h.queue.sync { h.transport.completeStart() }
        h.queue.sync {
            XCTAssertEqual(h.source.opens, 1)
            h.source.completeOpen(RouterProxyError.refused)
        }
        h.drain()
        h.queue.sync {
            XCTAssertEqual(h.source.reads, 0)
            XCTAssertTrue(h.transport.sends.isEmpty)
            XCTAssertTrue(h.transport.receiveLimits.isEmpty)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testApplicationBackpressureWaitsForNetworkWriteCompletion() {
        let h = Harness()
        h.authenticateAndOpen()
        let payload = Data("client bytes".utf8)
        h.queue.sync { h.source.completeRead(payload) }
        h.drain()
        h.queue.sync {
            XCTAssertEqual(h.transport.sends, [payload])
            XCTAssertEqual(h.source.reads, 1, "No second read while the first write is pending")
            h.transport.completeSend()
            XCTAssertEqual(h.source.reads, 2)
            h.relay.cancel()
        }
    }

    func testRemoteBackpressureWaitsForApplicationWriteCompletion() {
        let h = Harness()
        h.authenticateAndOpen()
        let payload = Data("server bytes".utf8)
        h.queue.sync { h.transport.completeReceive(payload) }
        h.queue.sync {
            XCTAssertEqual(h.source.writes, [payload])
            XCTAssertEqual(h.transport.receiveLimits, [65_536])
            h.source.completeWrite()
        }
        h.drain()
        h.queue.sync {
            XCTAssertEqual(h.transport.receiveLimits, [65_536, 65_536])
            h.relay.cancel()
        }
    }

    func testOversizedApplicationChunkFailsClosedWithoutForwarding() {
        let h = Harness()
        h.authenticateAndOpen()
        h.queue.sync { h.source.completeRead(Data(repeating: 0, count: 1_048_577)) }
        h.drain()
        h.queue.sync {
            XCTAssertTrue(h.transport.sends.isEmpty)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
            XCTAssertNotNil(h.source.readCloses.first!)
        }
    }

    func testNetworkLossClosesBothDirectionsWithoutRetryingOrCreatingDirectTransport() {
        let h = Harness()
        h.authenticateAndOpen()
        h.queue.sync {
            h.transport.onFailure?(RouterProxyError.closed)
            XCTAssertEqual(h.transport.starts, 1)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.source.readCloses.count, 1)
            XCTAssertEqual(h.source.writeCloses.count, 1)
            XCTAssertNotNil(h.source.readCloses.first!)
            XCTAssertNotNil(h.source.writeCloses.first!)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testCancellationIgnoresLateHandshakeCallbackAndFinishesOnlyOnce() {
        let h = Harness()
        h.start()
        h.queue.sync {
            h.relay.cancel()
            h.transport.completeStart()
            h.relay.cancel()
            XCTAssertEqual(h.source.opens, 0)
            XCTAssertEqual(h.source.reads, 0)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testRemoteEOFAllowsApplicationHalfCloseBeforeFinalCancellation() {
        let h = Harness()
        h.authenticateAndOpen()
        h.queue.sync {
            h.transport.completeReceive(Data(), complete: true)
            XCTAssertEqual(h.source.writeCloses.count, 1)
            XCTAssertNil(h.source.writeCloses.first!)
            XCTAssertEqual(h.transport.cancels, 0)
            XCTAssertEqual(h.finishes, 0)
            h.source.completeRead(Data())
        }
        h.drain()
        h.queue.sync {
            XCTAssertEqual(h.transport.finishes, 1)
            XCTAssertEqual(h.transport.cancels, 0)
            h.transport.completeFinish()
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
            XCTAssertTrue(h.source.readCloses.allSatisfy { $0 == nil })
            XCTAssertTrue(h.source.writeCloses.allSatisfy { $0 == nil })
        }
    }
}
