// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SnykDesk",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SnykDesk", targets: ["SnykDesk"])
    ],
    targets: [
        .target(name: "SnykDeskCore"),
        .executableTarget(name: "SnykDesk", dependencies: ["SnykDeskCore"]),
        .testTarget(name: "SnykDeskCoreTests", dependencies: ["SnykDeskCore"])
    ]
)
