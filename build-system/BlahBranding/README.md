# Blah branding

`branding.bzl` wraps the app's plist fragments and string resources before Apple
resource compilation and signing. It preserves resource names, localization keys,
bundle identifiers and URL schemes. `resources.py` owns the resource text policy.

[`BlahBranding`](../../submodules/BlahBranding/) applies the same naming to downloaded
localization templates and maps in-app service logos to the existing Blah asset.
Presentation strings are branded before argument interpolation, so formatted text
ranges and user-provided names remain correct. The app icon and display name are
owned by `Telegram/BUILD` and `Telegram/Telegram-iOS/Telegram.icon`.

When rebasing, keep the small integration hooks in `Telegram/BUILD`,
`GenerateStrings.py`, `AppBundle` and `LegacyComponents`. Keep source localization
catalogues and protocol names intact. Build with the normal full-app command in
[`CLAUDE.md`](../../CLAUDE.md); no post-signing bundle rewrite is required.
