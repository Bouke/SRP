// swift-tools-version:4.2

import PackageDescription

let package = Package(
    name: "SRP",
    products: [
        .library(name: "SRP", targets: ["SRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/IBM-Swift/BlueCryptor.git", from: "1.0.31"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.0.0"),
    ],
    targets: [
        .target(name: "SRP", dependencies: ["Cryptor", "BigInt"], path: "Sources"),
        .testTarget(name: "SRPTests", dependencies: ["Cryptor", "SRP"]),
    ]
)
