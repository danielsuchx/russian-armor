import XCTest
@testable import RussianArmour

final class HappVPNDiscoveryTests: XCTestCase {
    private func service(_ id: String = "profile", provider: String = HappVPNDiscovery.providerIdentifier,
                         connected: Bool = true, interface: String? = "utun6") -> HappVPNDiscovery.Service {
        .init(id: id, provider: provider, connected: connected, interface: interface)
    }

    func testLiveConnectedHappDiscovery() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["RUSSIAN_ARMOUR_TEST_HAPP"] == "1", "Requires an active Happ connection")
        guard case .connected(let interface, let isPrimary) = HappVPNDiscovery.read() else {
            return XCTFail("Happ service is not connected or cannot be identified")
        }
        XCTAssertTrue(interface.hasPrefix("utun"))
        XCTAssertTrue(isPrimary, "Happ is not the primary IPv4 service")
    }

    func testRequiresConnectedHappServiceAndMatchingPrimaryRoute() {
        let item = service()
        XCTAssertEqual(HappVPNDiscovery.evaluate([item], primaryService: "profile", primaryInterface: "utun6"),
                       .connected(interface: "utun6", isPrimaryIPv4: true))
        XCTAssertEqual(HappVPNDiscovery.evaluate([item], primaryService: "other", primaryInterface: "utun6"),
                       .connected(interface: "utun6", isPrimaryIPv4: false))
        XCTAssertEqual(HappVPNDiscovery.evaluate([item], primaryService: "profile", primaryInterface: "en0"),
                       .connected(interface: "utun6", isPrimaryIPv4: false))
    }

    func testDoesNotUseUnrelatedVPNOrDisconnectedService() {
        XCTAssertEqual(HappVPNDiscovery.evaluate([service(provider: "other")], primaryService: nil, primaryInterface: nil), .unavailable)
        XCTAssertEqual(HappVPNDiscovery.evaluate([service(connected: false)], primaryService: nil, primaryInterface: nil), .disconnected)
    }

    func testRefusesAmbiguousOrMalformedInterfaces() {
        XCTAssertEqual(HappVPNDiscovery.evaluate([service(), service("other")], primaryService: "profile", primaryInterface: "utun6"), .ambiguous)
        for name in [nil, "en0", "utun", "utun6\npass out all", "utun999999999999999999999"] as [String?] {
            XCTAssertEqual(HappVPNDiscovery.evaluate([service(interface: name)], primaryService: "profile", primaryInterface: name), .unavailable)
        }
    }
}
