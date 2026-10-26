// swift-tools-version: 6.4
import PackageDescription

// Native package dependencies consumed by Bazel through rules_swift_package_manager.
let package = Package(
    name: "TelegramDependencies",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        .package(url: "https://github.com/UInt8Co/BlahDiem.git", revision: "ab0297ce17280ae500944253d37d025ac9b2e23f"),
        .package(url: "https://github.com/UInt8Co/diem.git", revision: "1b47c2eee6195b0fb91d0649e0206274abc34a28"),
    ],
    targets: [
        .testTarget(name: "BlahDiemPackageTests", dependencies: [
            .product(name: "BlahDiem", package: "BlahDiem"),
            .product(name: "DiemSwiftCrypto", package: "diem"),
        ], path: "Tests"),
    ]
)
