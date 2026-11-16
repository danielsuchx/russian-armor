// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RussianArmour",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "RussianArmour", targets: ["RussianArmour"]),
        .executable(name: "ArmourProxyExtension", targets: ["ArmourProxyExtension"])
    ],
    targets: [
        .target(name: "ArmourCore"),
        .executableTarget(name: "RussianArmour", dependencies: ["ArmourCore"]),
        .executableTarget(name: "ArmourProxyExtension", dependencies: ["ArmourCore"]),
        .testTarget(name: "ArmourCoreTests", dependencies: ["ArmourCore"]),
        .testTarget(name: "ArmourProxyExtensionTests", dependencies: ["ArmourProxyExtension", "ArmourCore"]),
        .testTarget(name: "RussianArmourTests", dependencies: ["RussianArmour", "ArmourCore"])
    ]
)
