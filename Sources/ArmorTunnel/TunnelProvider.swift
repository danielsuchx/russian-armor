import Foundation

/// The privileged reader only inspects these providers. The kernel socket and
/// the running executable's code requirement must both match on every read.
enum TunnelProvider: Equatable {
    case clash, hiddifyService, hiddifyExtension

    static func candidate(executable: String, uid: uid_t) -> Self? {
        let name = URL(fileURLWithPath: executable).lastPathComponent
        switch name {
        case "verge-mihomo", "verge-mihomo-alpha":
            return uid == 0 ? .clash : nil
        case "Hiddify" where uid == 0:
            let base = "/Library/Application Support/Hiddify/"
            let binary = "/Hiddify.app/Contents/MacOS/Hiddify"
            guard executable == base + "AdminBgService" + binary ||
                  executable == base + "TunnelService" + binary else { return nil }
            return .hiddifyService
        case "HiddifyPacketTunnel":
            return .hiddifyExtension
        default:
            return nil
        }
    }

    var requirement: String {
        switch self {
        case .clash:
            return #"anchor apple generic and certificate leaf[subject.OU] = "JPH3Z7PPBB" and (identifier "verge-mihomo" or identifier "verge-mihomo-alpha")"#
        case .hiddifyExtension:
            return #"anchor apple generic and certificate leaf[subject.OU] = "M7Q8ASP66Z" and identifier "apple.hiddify.com.HiddifyPacketTunnel""#
        case .hiddifyService:
            // Official v5.5.5 GitHub DMG and installer PKG, arm64 and x86_64.
            // Ad-hoc signatures have no team identity across releases.
            return #"identifier "apple.hiddify.com" and ((anchor apple generic and certificate leaf[subject.OU] = "M7Q8ASP66Z") or cdhash H"846d7950f191f8a8bb9fd0fd8a98ad56c493e538" or cdhash H"948e8be783a2e8bb40b615d70bd40e27013bc288")"#
        }
    }
}
