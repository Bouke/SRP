import PackageDescription

let package = Package(
    name: "SRP",
    dependencies: [
        .Package(url: "https://github.com/Bouke/CommonCrypto.git", majorVersion: 1),
        .Package(url: "https://github.com/Bouke/Bignum.git", majorVersion: 1),
    ]
)
