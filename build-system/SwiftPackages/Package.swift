// swift-tools-version: 6.3
import PackageDescription

// Native package dependencies consumed by Bazel through rules_swift_package_manager.
let package = Package(
    name: "TelegramDependencies",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        .package(url: "https://github.com/UInt8Co/BlahDiem.git", revision: "bd89a76e8f144468d24b5d83df56709300785c8f"),
        .package(url: "https://github.com/UInt8Co/diem.git", revision: "ea6383c39389fc700f15137c6e2a137b524724dc"),
    ]
)
