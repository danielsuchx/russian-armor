// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RussianArmor",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "RussianArmor", targets: ["RussianArmor"]),
        .executable(name: "ArmorFirewall", targets: ["ArmorFirewall"])
    ],
    targets: [
        .target(name: "ArmorCore"),
        .target(name: "BoundCurl", linkerSettings: [.linkedLibrary("curl")]),
        .target(name: "ArmorTunnel", dependencies: ["ArmorCore", "BoundCurl"]),
        .executableTarget(name: "ArmorClashReader", dependencies: ["ArmorTunnel"]),
        .executableTarget(name: "ArmorFirewall", dependencies: ["ArmorCore", "ArmorTunnel"]),
        .executableTarget(name: "RussianArmor", dependencies: ["ArmorCore", "ArmorTunnel"],
                          resources: [.copy("Resources/AppIcon.icns")]),
        .testTarget(name: "ArmorCoreTests", dependencies: ["ArmorCore"]),
        .testTarget(name: "ArmorFirewallTests", dependencies: ["ArmorFirewall", "ArmorCore"]),
        .testTarget(name: "RussianArmorTests", dependencies: ["RussianArmor", "ArmorCore", "ArmorTunnel"])
    ]
)
