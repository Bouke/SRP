// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "SRP",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(name: "SRP", targets: ["SRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.0"),
    ],
    targets: [
        .target(name: "SRP", dependencies: ["BigInt", "Crypto"], path: "Sources"),
        .testTarget(name: "SRPTests", dependencies: ["Crypto", "SRP"]),
    ]
)
