// swift-tools-version: 6.4
import PackageDescription

// Native package dependencies consumed by Bazel through rules_swift_package_manager.
let package = Package(
    name: "TelegramDependencies",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        .package(url: "https://github.com/UInt8Co/BlahDiem.git", revision: "601501e8d431a3898daa22f5ba07ab265f06a9d1"),
        .package(url: "https://github.com/UInt8Co/diem.git", revision: "55780087db25c771b97b7947a0419befe828ce80"),
    ],
    targets: [
        .testTarget(name: "BlahDiemPackageTests", dependencies: [
            .product(name: "BlahDiem", package: "BlahDiem"),
            .product(name: "DiemSwiftCrypto", package: "diem"),
        ], path: "Tests"),
    ]
)
