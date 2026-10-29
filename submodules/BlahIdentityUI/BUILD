load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")

swift_library(
    name = "BlahIdentityUI",
    module_name = "BlahIdentityUI",
    srcs = glob(["Sources/**/*.swift"]),
    deps = [
        "//submodules/BlahIdentity", "@swiftpkg_blahdiem//:BlahDiem",
        "//submodules/TelegramCore", "//submodules/TelegramPresentationData", "//submodules/Display",
        "//submodules/ItemListUI", "//submodules/SSignalKit/SwiftSignalKit",
        "//submodules/AsyncDisplayKit", "//submodules/AccountContext",
        "//submodules/SolidRoundedButtonNode", "//submodules/PresentationDataUtils",
        "//submodules/QrCode", "//submodules/QrCodeUI",
    ],
    visibility = ["//visibility:public"],
)
