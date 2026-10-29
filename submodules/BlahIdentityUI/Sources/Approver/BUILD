load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

# A subpackage keeps the approver out of BlahIdentityUI's recursive source glob.
# The wizard depends on QrCodeUI; the scanner can depend on this target without a cycle.
swift_library(
    name = "BlahDeviceLinkUI",
    module_name = "BlahDeviceLinkUI",
    srcs = glob(["*.swift"]),
    deps = [
        "//submodules/BlahIdentity",
        "//submodules/TelegramCore",
        "//submodules/TelegramPresentationData",
        "//submodules/Display",
        "//submodules/ItemListUI",
        "//submodules/SSignalKit/SwiftSignalKit",
    ],
    visibility = ["//visibility:public"],
)
