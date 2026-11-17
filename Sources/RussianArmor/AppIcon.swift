import AppKit
import Foundation

enum AppIcon {
    static let image: NSImage? = {
        // Resolve SwiftPM resources relative to the executable. Bundle.module's
        // generated fallback embeds the developer's absolute build directory.
        let resources = Bundle.main.executableURL?.deletingLastPathComponent()
            .appendingPathComponent("RussianArmor_RussianArmor.bundle")
        let packageBundle = resources.flatMap { Bundle(url: $0) }
        let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
            ?? packageBundle?.url(forResource: "AppIcon", withExtension: "icns")
        guard let url else {
            return nil
        }
        return NSImage(contentsOf: url)
    }()
}
