import CryptoKit
import Foundation

enum UpdateSignature {
    static func payload(for update: GitHubUpdate) -> Data {
        Data("Russian Armor release\nversion=\(update.version)\nsize=\(update.size)\nsha256=\(update.sha256)\n".utf8)
    }

    static func verify(_ signatureText: Data, update: GitHubUpdate, publicKey: Data) throws {
        guard signatureText.count <= 256,
              let text = String(data: signatureText, encoding: .utf8),
              let signature = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
              key.isValidSignature(signature, for: payload(for: update)) else { throw AppUpdateError.signature }
    }

    static func bundledPublicKey() throws -> Data {
        guard let url = Bundle.main.url(forResource: "UpdatePublicKey", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8),
              let key = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)), key.count == 32 else {
            throw AppUpdateError.signature
        }
        return key
    }
}
