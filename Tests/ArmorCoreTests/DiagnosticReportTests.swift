import ArmorCore
import Foundation
import XCTest

final class DiagnosticReportTests: XCTestCase {
    func testJSONUsesOnlyAllowlistedFieldsAndStableMachineReadableStates() throws {
        let report = DiagnosticReport(createdAt: Date(timeIntervalSince1970: 1000), appVersion: "0.2.2",
                                      vpnLocation: .router, controllerState: .paused,
                                      checks: [.init(.egress, .unavailable, .requestFailed)])
        let data = try report.jsonData()
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(root.keys), ["schemaVersion", "createdAt", "appVersion", "vpnLocation", "controllerState", "checks"])
        XCTAssertEqual(root["schemaVersion"] as? Int, 1)
        XCTAssertEqual(root["createdAt"] as? String, "1970-01-01T00:16:40Z")
        let check = try XCTUnwrap((root["checks"] as? [[String: String]])?.first)
        XCTAssertEqual(check, ["id": "egress", "status": "unavailable", "finding": "requestFailed"])
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        XCTAssertEqual(try decoder.decode(DiagnosticReport.self, from: data), report)
        XCTAssertEqual(data, try report.jsonData())
    }

    func testVersionMetadataCannotIntroduceSecretsPathsOrAddresses() throws {
        for value in ["/Users/private", "https://user:password@example.org", "203.0.113.17/32",
                      "203.0.113.17", "token=secret", "1..0", "1.2\n", "１.２", "99999.2", ""] {
            let report = DiagnosticReport(createdAt: .distantPast, appVersion: value, vpnLocation: .unspecified,
                                          controllerState: .unavailable, checks: [])
            XCTAssertNil(report.appVersion, value)
            let root = try XCTUnwrap(JSONSerialization.jsonObject(with: report.jsonData()) as? [String: Any])
            XCTAssertNil(root["appVersion"])
        }
    }
}
