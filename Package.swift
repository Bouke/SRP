import PackageDescription

let package = Package(
    name: "SRP",
    dependencies: [
        .Package(url: "https://github.com/IBM-Swift/BlueCryptor.git", majorVersion: 0, minor: 8),
        .Package(url: "https://github.com/lorentey/BigInt.git", majorVersion: 2, minor: 1),
    ]
)
