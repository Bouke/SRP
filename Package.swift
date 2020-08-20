// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "SRP",
    products: [
        .library(name: "SRP", targets: ["SRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.0.0"),
        .package(url: "https://github.com/Bouke/swift-crypto.git", .exact("1.1.0-rc.2-patched")),
    ],
    targets: [
        .target(name: "SRP", dependencies: ["BigInt", "Crypto"], path: "Sources"),
        .testTarget(name: "SRPTests", dependencies: ["Crypto", "SRP"]),
    ]
)
