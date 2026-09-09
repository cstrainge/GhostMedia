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
        .library(name: "GhostMediaRuntime", targets: ["GhostMediaRuntime"]),
        .library(name: "GhostMediaProtocolBridge", targets: ["GhostMediaProtocolBridge"]),
        .library(name: "GhostMediaAppleCore", targets: ["GhostMediaAppleCore"]),
        .library(name: "GhostMediaAppleSecurity", targets: ["GhostMediaAppleSecurity"]),
        .library(name: "GhostMediaAppleUI", targets: ["GhostMediaAppleUI"]),
        .executable(name: "GhostMediaAppleHarness", targets: ["GhostMediaAppleHarness"]),
        .executable(name: "GhostMediaWinControlProbe", targets: ["GhostMediaWinControlProbe"]),
        .executable(name: "GhostMediaMac", targets: ["GhostMediaMac"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/krzyzanowskim/OpenSSL-Package.git",
            exact: "3.6.3000"
        ),
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
            name: "GhostMediaRuntime",
            dependencies: [
                "GhostMediaCore",
                .product(name: "OpenSSL", package: "OpenSSL-Package"),
            ],
            path: "runtime",
            exclude: ["CMakeLists.txt", "tests"],
            sources: ["core"],
            publicHeadersPath: "include",
            cxxSettings: [.headerSearchPath("include")]
        ),
        .target(
            name: "GhostMediaAppleCore",
            path: "AppleOutputServer/Sources/GhostMediaAppleCore"
        ),
        .target(
            name: "GhostMediaAppleSecurity",
            dependencies: ["GhostMediaProtocolBridge", "GhostMediaRuntime"],
            path: "AppleOutputServer/Sources/GhostMediaAppleSecurity"
        ),
        .target(
            name: "GhostMediaAppleUI",
            dependencies: ["GhostMediaAppleCore", "GhostMediaProtocolBridge"],
            path: "AppleOutputServer/Sources/GhostMediaAppleUI"
        ),
        .executableTarget(
            name: "GhostMediaAppleHarness",
            dependencies: ["GhostMediaProtocolBridge", "GhostMediaAppleSecurity"],
            path: "AppleOutputServer/Sources/GhostMediaAppleHarness"
        ),
        .executableTarget(
            name: "GhostMediaMac",
            dependencies: ["GhostMediaAppleCore", "GhostMediaAppleUI"],
            path: "AppleOutputServer/Sources/GhostMediaMac"
        ),
        .executableTarget(
            name: "GhostMediaWinControlProbe",
            dependencies: ["GhostMediaCore", "GhostMediaRuntime"],
            path: "WinDevice/tools/control_probe"
        ),
        .executableTarget(
            name: "GhostMediaRuntimeTests",
            dependencies: [
                "GhostMediaRuntime",
                .product(name: "OpenSSL", package: "OpenSSL-Package"),
            ],
            path: "runtime/tests"
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
        .testTarget(
            name: "GhostMediaAppleSecurityTests",
            dependencies: ["GhostMediaAppleSecurity", "GhostMediaProtocolBridge"],
            path: "AppleOutputServer/Tests/GhostMediaAppleSecurityTests"
        ),
    ],
    swiftLanguageModes: [.v6],
    cxxLanguageStandard: .cxx20
)
