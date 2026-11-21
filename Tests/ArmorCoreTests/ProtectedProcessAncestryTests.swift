import ArmorCore
import XCTest

final class ProtectedProcessAncestryTests: XCTestCase {
    private func node(_ pid: Int32, parent: Int32 = 1, start: UInt64 = 10,
                      micros: UInt64 = 0, application: ProtectedApplication? = nil) -> ProtectedProcessAncestry.Node {
        .init(identity: .init(pid: pid, startSeconds: start, startMicroseconds: micros),
              parentPID: parent, application: application)
    }

    func testNewChildIsClassifiedBeforeItAppearsInGUIPolicy() {
        for application in ProtectedApplication.allCases {
            let nodes = [node(30, parent: 20, start: 12), node(20, parent: 10, start: 11),
                         node(10, application: application)]
            let byPID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.identity.pid, $0) })
            XCTAssertEqual(ProtectedProcessAncestry.application(for: nodes[0].identity, read: { byPID[$0] }), application)
        }
    }

    func testUnrelatedApplicationsAndMissingParentsStayUnclassified() {
        let source = node(30, parent: 20)
        for nodes in [[source], [source, node(20)], [source, node(10, application: .desktop)]] {
            let byPID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.identity.pid, $0) })
            XCTAssertNil(ProtectedProcessAncestry.application(for: source.identity, read: { byPID[$0] }))
        }
    }

    func testReusedSourcePIDDoesNotInheritPreviousIdentity() {
        let source = node(30, application: .desktop)
        let replacement = node(30, start: 11, application: .code)
        XCTAssertNil(ProtectedProcessAncestry.application(for: source.identity, read: { _ in replacement }))
    }

    func testReusedParentPIDCannotClassifyAnOlderChild() {
        let source = node(30, parent: 20, micros: 1)
        for parent in [node(20, start: 11, application: .desktop),
                       node(20, micros: 2, application: .desktop)] {
            let byPID = [source.identity.pid: source, parent.identity.pid: parent]
            XCTAssertNil(ProtectedProcessAncestry.application(for: source.identity, read: { byPID[$0] }))
        }
    }

    func testCyclesAndExcessiveDepthCannotHangTheNetworkFilter() {
        let source = node(30, parent: 20)
        let byPID = [Int32(30): source, Int32(20): node(20, parent: 30)]
        XCTAssertNil(ProtectedProcessAncestry.application(for: source.identity, read: { byPID[$0] }))
        var reads = 0
        XCTAssertNil(ProtectedProcessAncestry.application(for: source.identity, read: { pid in
            reads += 1
            return self.node(pid, parent: pid + 1)
        }))
        XCTAssertEqual(reads, 128)
    }
}
