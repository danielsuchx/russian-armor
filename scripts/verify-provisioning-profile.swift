import CryptoKit
import Foundation
import Security

// Verify the CMS signature before `security cms -D` is used for plist decoding.
// The security command's decoder exit code alone does not reliably reject an
// invalid CMS signer. No keychain imports or network trust fetches are needed.
private func reject() -> Never {
    FileHandle.standardError.write(Data("Provisioning profile: invalid Apple signature or trust chain.\n".utf8))
    exit(1)
}

private func hasExtension(_ certificate: SecCertificate, oid: String) -> Bool {
    guard let values = SecCertificateCopyValues(certificate, [oid] as CFArray, nil) as? [String: Any],
          values[oid] != nil else { return false }
    return true
}

let encoded = FileHandle.standardInput.readDataToEndOfFile()
guard (1...(2 * 1024 * 1024)).contains(encoded.count) else { reject() }
var optionalDecoder: CMSDecoder?
guard CMSDecoderCreate(&optionalDecoder) == errSecSuccess, let decoder = optionalDecoder else { reject() }
let updateStatus = encoded.withUnsafeBytes { bytes in
    guard let baseAddress = bytes.baseAddress else { reject() }
    return CMSDecoderUpdateMessage(decoder, baseAddress, bytes.count)
}
guard updateStatus == errSecSuccess, CMSDecoderFinalizeMessage(decoder) == errSecSuccess else { reject() }
var signerCount = 0
guard CMSDecoderGetNumSigners(decoder, &signerCount) == errSecSuccess, signerCount == 1 else { reject() }
var signerStatus = CMSSignerStatus.unsigned
var optionalTrust: SecTrust?
guard CMSDecoderCopySignerStatus(decoder, 0, SecPolicyCreateBasicX509(), false, &signerStatus, &optionalTrust, nil) == errSecSuccess,
      signerStatus == .valid, let trust = optionalTrust,
      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
      SecTrustEvaluateWithError(trust, nil),
      let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], chain.count >= 3,
      let leaf = chain.first, let root = chain.last else { reject() }

// Public Apple production roots; no developer-specific identity is checked in.
// An arbitrary system-trusted developer or locally added CA cannot mint profiles.
let appleRootSHA256: Set<String> = [
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024", // Apple Root CA
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050", // G2
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"  // G3
]
let rootHash = SHA256.hash(data: SecCertificateCopyData(root) as Data).map { String(format: "%02x", $0) }.joined()
guard appleRootSHA256.contains(rootHash),
      hasExtension(leaf, oid: "1.2.840.113635.100.4.11"),
      chain.dropFirst().dropLast().contains(where: { hasExtension($0, oid: "1.2.840.113635.100.6.2.1") }) else { reject() }
