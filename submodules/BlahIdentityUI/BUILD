load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_library(
    name = "BlahIdentityUI",
    module_name = "BlahIdentityUI",
    srcs = glob(["Sources/**/*.swift"]),
    deps = [
        "//submodules/BlahIdentity", "//third-party/BlahDiem:BlahDiem",
        "//submodules/TelegramCore", "//submodules/TelegramPresentationData", "//submodules/Display",
        "//submodules/ItemListUI", "//submodules/SSignalKit/SwiftSignalKit",
    ],
    visibility = ["//visibility:public"],
)
