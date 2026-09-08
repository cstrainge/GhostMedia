// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "GhostMedia",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "GhostMediaCore", targets: ["GhostMediaCore"]),
        .library(name: "GhostMediaProtocolBridge", targets: ["GhostMediaProtocolBridge"]),
        .library(name: "GhostMediaAppleCore", targets: ["GhostMediaAppleCore"]),
        .library(name: "GhostMediaAppleUI", targets: ["GhostMediaAppleUI"]),
        .executable(name: "GhostMediaAppleHarness", targets: ["GhostMediaAppleHarness"]),
        .executable(name: "GhostMediaMac", targets: ["GhostMediaMac"]),
    ],
    targets: [
        .target(
            name: "GhostMediaCore",
            path: "shared",
            exclude: ["CMakeLists.txt", "tests"],
            sources: ["core"],
            publicHeadersPath: "include",
            cxxSettings: [.headerSearchPath("include")]
        ),
        .target(
            name: "GhostMediaProtocolBridge",
            dependencies: ["GhostMediaCore"],
            path: "AppleOutputServer/Sources/GhostMediaProtocolBridge"
        ),
        .target(
            name: "GhostMediaAppleCore",
            path: "AppleOutputServer/Sources/GhostMediaAppleCore"
        ),
        .target(
            name: "GhostMediaAppleUI",
            dependencies: ["GhostMediaAppleCore", "GhostMediaProtocolBridge"],
            path: "AppleOutputServer/Sources/GhostMediaAppleUI"
        ),
        .executableTarget(
            name: "GhostMediaAppleHarness",
            dependencies: ["GhostMediaProtocolBridge"],
            path: "AppleOutputServer/Sources/GhostMediaAppleHarness"
        ),
        .executableTarget(
            name: "GhostMediaMac",
            dependencies: ["GhostMediaAppleCore", "GhostMediaAppleUI"],
            path: "AppleOutputServer/Sources/GhostMediaMac"
        ),
        .testTarget(
            name: "GhostMediaAppleCoreTests",
            dependencies: ["GhostMediaAppleCore"],
            path: "AppleOutputServer/Tests/GhostMediaAppleCoreTests"
        ),
        .testTarget(
            name: "GhostMediaProtocolBridgeTests",
            dependencies: ["GhostMediaProtocolBridge"],
            path: "AppleOutputServer/Tests/GhostMediaProtocolBridgeTests"
        ),
    ],
    swiftLanguageModes: [.v6],
    cxxLanguageStandard: .cxx20
)
