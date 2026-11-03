// swift-tools-version: 6.4
import PackageDescription

// Native package dependencies consumed by Bazel through rules_swift_package_manager.
let package = Package(
    name: "TelegramDependencies",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        .package(url: "https://github.com/UInt8Co/BlahDiem.git", revision: "f21f4a1ae35ddef437aab3ad9c16a58024f1d36f"),
        .package(url: "https://github.com/UInt8Co/diem.git", revision: "f8da6ebc131649d5a4eb220fd3bb56bc5d3ae4d5"),
    ],
    targets: [
        .testTarget(name: "BlahDiemPackageTests", dependencies: [
            .product(name: "BlahDiem", package: "BlahDiem"),
            .product(name: "DiemSwiftCrypto", package: "diem"),
        ], path: "Tests"),
    ]
)
