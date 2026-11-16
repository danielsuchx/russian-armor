import Foundation
import NetworkExtension
import XCTest
@testable import ArmourProxyExtension

final class DNSFlowRelayTests: XCTestCase {
    private final class Source: DNSProxySourceFlow {
        var opens = 0
        var reads = 0
        var replies: [[Data]] = []
        var replyEndpoints: [[NWHostEndpoint]] = []
        var readCloses: [NSError?] = []
        var writeCloses: [NSError?] = []
        var openCompletion: ((Error?) -> Void)?
        var readCompletion: (([Data]?, [NWHostEndpoint]?, Error?) -> Void)?
        var writeCompletion: ((Error?) -> Void)?
        func open(completion: @escaping (Error?) -> Void) { opens += 1; openCompletion = completion }
        func readDatagrams(completion: @escaping ([Data]?, [NWHostEndpoint]?, Error?) -> Void) { reads += 1; readCompletion = completion }
        func writeDatagrams(_ datagrams: [Data], sentBy endpoints: [NWHostEndpoint], completion: @escaping (Error?) -> Void) {
            replies.append(datagrams); replyEndpoints.append(endpoints); writeCompletion = completion
        }
        func closeRead(_ error: NSError?) { readCloses.append(error) }
        func closeWrite(_ error: NSError?) { writeCloses.append(error) }
        func completeOpen() { let callback = openCompletion; openCompletion = nil; callback?(nil) }
        func completeRead(_ datagrams: [Data], endpoints: [NWHostEndpoint]) {
            let callback = readCompletion; readCompletion = nil; callback?(datagrams, endpoints, nil)
        }
        func completeWrite() { let callback = writeCompletion; writeCompletion = nil; callback?(nil) }
    }

    private final class Transport: DNSRouterTransport {
        var onFailure: ((Error) -> Void)?
        var starts = 0
        var sends: [Data] = []
        var exactReads: [Int] = []
        var cancels = 0
        var startCompletion: ((Error?) -> Void)?
        var sendCompletion: ((Error?) -> Void)?
        var receiveCompletion: ((Data?, Error?) -> Void)?
        func start(completion: @escaping (Error?) -> Void) { starts += 1; startCompletion = completion }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { sends.append(data); sendCompletion = completion }
        func finishSending(completion: @escaping (Error?) -> Void) { XCTFail("DNS exchange does not half-close before its reply") }
        func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void) { XCTFail("DNS must use framed reads") }
        func receiveExactly(_ count: Int, completion: @escaping (Data?, Error?) -> Void) { exactReads.append(count); receiveCompletion = completion }
        func cancel() { cancels += 1 }
        func completeStart(_ error: Error? = nil) { let callback = startCompletion; startCompletion = nil; callback?(error) }
        func completeSend() { let callback = sendCompletion; sendCompletion = nil; callback?(nil) }
        func completeRead(_ data: Data) { let callback = receiveCompletion; receiveCompletion = nil; callback?(data, nil) }
    }

    private final class Harness {
        let queue = DispatchQueue(label: "DNSFlowRelayTests.\(UUID())")
        let source = Source()
        let transport = Transport()
        var destinations: [String] = []
        var finishes = 0
        lazy var relay = DNSFlowRelay(flow: source, queue: queue, makeTransport: { [unowned self] host in
            self.destinations.append(host)
            return self.transport
        }, onFinish: { [weak self] in self?.finishes += 1 })
        let query = Data([0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        let endpoint = NWHostEndpoint(hostname: "1.1.1.1", port: "53")
        func open() {
            queue.sync { relay.start(); source.completeOpen() }
            queue.sync {}
        }
        func deliver(_ datagrams: [Data], endpoints: [NWHostEndpoint]) {
            queue.sync { source.completeRead(datagrams, endpoints: endpoints) }
            queue.sync {}
        }
    }

    func testNonDNSDatagramIsDeniedBeforeOpeningAnyRouterConnection() {
        let h = Harness()
        h.open()
        h.deliver([h.query], endpoints: [NWHostEndpoint(hostname: "203.0.113.10", port: "443")])
        h.queue.sync {
            XCTAssertTrue(h.destinations.isEmpty)
            XCTAssertEqual(h.transport.starts, 0)
            XCTAssertEqual(h.source.readCloses.count, 1)
            XCTAssertEqual(h.source.writeCloses.count, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testOversizedBatchIsDeniedWithoutCreatingTransport() {
        let h = Harness()
        h.open()
        h.deliver(Array(repeating: h.query, count: 17), endpoints: Array(repeating: h.endpoint, count: 17))
        h.queue.sync {
            XCTAssertTrue(h.destinations.isEmpty)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testAuthenticationFailureNeverSendsDNSInPlaintextOrRetriesAnotherServer() {
        let h = Harness()
        h.open()
        h.deliver([h.query], endpoints: [h.endpoint])
        h.queue.sync {
            XCTAssertEqual(h.destinations, ["1.1.1.1"])
            h.transport.completeStart(RouterProxyError.refused)
            XCTAssertTrue(h.transport.sends.isEmpty)
            XCTAssertTrue(h.source.replies.isEmpty)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testDNSIsTCPFramedAndReplyWrittenOnlyAfterMatchingTransactionID() {
        let h = Harness()
        h.open()
        h.deliver([h.query], endpoints: [h.endpoint])
        let response = Data([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0])
        h.queue.sync {
            h.transport.completeStart()
            XCTAssertEqual(h.transport.sends, [Data([0, 12]) + h.query])
            h.transport.completeSend()
            XCTAssertEqual(h.transport.exactReads, [2])
            h.transport.completeRead(Data([0, 12]))
            XCTAssertEqual(h.transport.exactReads, [2, 12])
            h.transport.completeRead(response)
            XCTAssertEqual(h.source.replies, [[response]])
            XCTAssertEqual(h.source.replyEndpoints.first?.first?.hostname, "1.1.1.1")
            XCTAssertEqual(h.source.reads, 1, "Next datagram read waits for app write completion")
            h.source.completeWrite()
        }
        h.queue.sync {}
        h.queue.sync {
            XCTAssertEqual(h.source.reads, 2)
            h.relay.cancel()
        }
    }

    func testMismatchedDNSTransactionIDClosesInsteadOfDeliveringAnswer() {
        let h = Harness()
        h.open()
        h.deliver([h.query], endpoints: [h.endpoint])
        h.queue.sync {
            h.transport.completeStart()
            h.transport.completeSend()
            h.transport.completeRead(Data([0, 12]))
            h.transport.completeRead(Data([0xff, 0xff, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]))
            XCTAssertTrue(h.source.replies.isEmpty)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }

    func testCancellationDropsPendingDNSAndIgnoresLateAuthentication() {
        let h = Harness()
        h.open()
        h.deliver([h.query], endpoints: [h.endpoint])
        h.queue.sync {
            h.relay.cancel()
            h.transport.completeStart()
            XCTAssertTrue(h.transport.sends.isEmpty)
            XCTAssertTrue(h.source.replies.isEmpty)
            XCTAssertEqual(h.transport.cancels, 1)
            XCTAssertEqual(h.finishes, 1)
        }
    }
}
