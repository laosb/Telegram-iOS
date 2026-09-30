load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_library(
    name = "Diem",
    module_name = "Diem",
    srcs = glob(["Diem/*.swift"]),
    visibility = ["//visibility:public"],
)
swift_library(
    name = "BlahDiem",
    module_name = "BlahDiem",
    srcs = glob(["BlahDiem/*.swift"]),
    deps = [":Diem"],
    visibility = ["//visibility:public"],
)
# Swift Crypto delegates to CryptoKit on Apple platforms. This re-export avoids
# building its portable BoringSSL implementation inside the iOS Bazel graph.
swift_library(
    name = "Crypto",
    module_name = "Crypto",
    srcs = ["Crypto.swift"],
)
swift_library(
    name = "DiemSwiftCrypto",
    module_name = "DiemSwiftCrypto",
    srcs = glob(["DiemSwiftCrypto/*.swift"]),
    deps = [":Diem", ":Crypto"],
    visibility = ["//visibility:public"],
)
