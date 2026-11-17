import AppKit
import Foundation

enum AppIcon {
    static let image: NSImage? = {
        let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
            ?? Bundle.module.url(forResource: "AppIcon", withExtension: "icns")
        guard let url else {
            return nil
        }
        return NSImage(contentsOf: url)
    }()
}
