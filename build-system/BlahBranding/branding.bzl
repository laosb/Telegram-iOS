"""Blah resource branding runs before Apple resource compilation and signing."""

load("//build-system/bazel-utils:plist_fragment.bzl", upstream_plist_fragment = "plist_fragment")

def _brand_resource(ctx, source, output):
    ctx.actions.run_shell(
        inputs = [source, ctx.file._processor],
        outputs = [output],
        command = 'python3 "$1" "$2" "$3"',
        arguments = [ctx.file._processor.path, source.path, output.path],
        mnemonic = "BlahBrandResources",
    )

def _brand_resources(ctx):
    outputs = []
    for source in ctx.files.srcs:
        output = ctx.actions.declare_file(ctx.label.name + "/" + source.short_path)
        _brand_resource(ctx, source, output)
        outputs.append(output)
    return [DefaultInfo(files = depset(outputs))]

blah_resources = rule(
    implementation = _brand_resources,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "_processor": attr.label(
            default = "//build-system/BlahBranding:resources.py",
            allow_single_file = True,
        ),
    },
)

def _brand_plist(ctx):
    _brand_resource(ctx, ctx.file.src, ctx.outputs.out)
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

_blah_plist = rule(
    implementation = _brand_plist,
    attrs = {
        "src": attr.label(allow_single_file = True),
        "extension": attr.string(mandatory = True),
        "_processor": attr.label(
            default = "//build-system/BlahBranding:resources.py",
            allow_single_file = True,
        ),
    },
    outputs = {"out": "%{name}.%{extension}"},
)

def plist_fragment(name, **kwargs):
    upstream_plist_fragment(name = name + "_Unbranded", **kwargs)
    _blah_plist(name = name, src = ":" + name + "_Unbranded", extension = kwargs["extension"])
