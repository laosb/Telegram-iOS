load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_library(
    name = "BlahIdentity",
    module_name = "BlahIdentity",
    srcs = glob(["Sources/**/*.swift"]),
    deps = ["@swiftpkg_blahdiem//:BlahDiem", "@swiftpkg_diem//:DiemSwiftCrypto"],
    visibility = ["//visibility:public"],
)
