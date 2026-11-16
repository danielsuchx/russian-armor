import CryptoKit
import Foundation
import Security

/// Authenticates the dedicated router endpoint without trusting the local LAN,
/// system CA substitutions, or certificates obtained from external URLs.
enum RouterTLSVerifier {
    static func validate(
        _ trust: SecTrust,
        certificateSHA256 expectedPin: Data,
        serverName: String,
        at date: Date = Date()
    ) -> Bool {
        // Set this BEFORE inspecting the chain: chain access may itself trigger
        // implicit trust evaluation, which must never fetch an AIA/OCSP URL.
        guard SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              expectedPin.count == 32,
              serverName == "russian-armour.router",
              let revocation = SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod | kSecRevocationNetworkAccessDisabled),
              SecTrustSetPolicies(trust, [SecPolicyCreateSSL(true, serverName as CFString), revocation] as CFArray) == errSecSuccess,
              SecTrustSetVerifyDate(trust, date as CFDate) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              let certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = certificates.first,
              Data(SHA256.hash(data: SecCertificateCopyData(leaf) as Data)) == expectedPin,
              SecTrustSetAnchorCertificates(trust, [leaf] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else {
            return false
        }
        // Exact pinned leaf is the only trust anchor; ordinary server SSL name,
        // key usage and validity checks still apply to this connection.
        return SecTrustEvaluateWithError(trust, nil)
    }
}
