// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WireNest",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "WireNestApp", targets: ["WireNestApp"]),
        .executable(name: "WireNestHelper", targets: ["WireNestHelper"]),
        .library(name: "WireNestCore", targets: ["WireNestCore"]),
    ],
    targets: [
        .target(name: "WireNestCore"),
        .executableTarget(name: "WireNestApp", dependencies: ["WireNestCore"]),
        .executableTarget(name: "WireNestHelper", dependencies: ["WireNestCore"]),
        .testTarget(name: "WireNestCoreTests", dependencies: ["WireNestCore"]),
    ]
)
