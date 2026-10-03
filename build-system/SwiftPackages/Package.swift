// swift-tools-version: 6.3
import PackageDescription

// Native package dependencies consumed by Bazel through rules_swift_package_manager.
let package = Package(
    name: "TelegramDependencies",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        .package(url: "https://github.com/UInt8Co/BlahDiem.git", revision: "f5ac01264bf404257393bd00fa31ef6694b9eb4b"),
        .package(url: "https://github.com/UInt8Co/diem.git", revision: "ea6383c39389fc700f15137c6e2a137b524724dc"),
    ]
)
