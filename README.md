# Telegram iOS Source Code Compilation Guide

We welcome all developers to use our API and source code to create applications on our platform.
There are several things we require from **all developers** for the moment.

## Blah identity flow

This fork requires iOS 18 or later. **Choose identity** opens the native Identity Manager,
also available in Settings. Connect to your home DC domain before creating an identity.
The DC publishes its signed profile at `/.well-known/blah/profile.cbor` and advertises a
plain TCP MTProto endpoint. iOS 18–25 supports Ed25519/P-256 DC profile signatures;
ML-DSA requires iOS 26. Its identity, database generation and signed version are
pinned per account; another home or identity requires another account slot. Unbound
legacy transport sessions require a fresh account.

Create a name on a Diem profile host, use a domain you host yourself, or import a
password-encrypted identity file. Shared BlahDiem CBOR/HPKE files containing identity
recovery authority are accepted; device-only files and JSON backups are unsupported.
Hosted identities publish automatically after changes and signup; failed publication
retains the signed revision and can be retried in Identity Manager. For your own domains,
publish the exported public `profile.cbor` at every listed HTTPS domain with content type
`application/cbor`, including the updated account number after signup, then sign in again.
Sign-in first uses the identity domain. Admission email appears only when the DC asks for
it; signup without email goes straight to the name form. Existing email-code and two-step
password screens complete the DC's additional factors. Identity Manager also manages
domains, devices, profile validity and renewal; publish every authority change.

Identity custody lives in Keychain independently of chat storage. Native BlahDiem uses
Secure Enclave P-256 device keys and seals the Ed25519 recovery key to another Secure
Enclave key. **Unlock with Face ID or Touch ID** is optional; there is no separate identity
passcode. Encrypted file export/import requires a nonempty backup password with no additional
length or complexity rules.
**Sync recovery with iCloud Keychain** is opt-in and synchronizes the recoverable identity
key and profile, not the hardware device keys. Recovery fetches the latest hosted profile,
enrolls a fresh Secure Enclave device, and requires publication. Native recovery exports
are for native recovery; they do not export the hardware device key as a browser identity.
Custody locks when leaving management, on backgrounding, or after 15 idle minutes;
continuing sign-in retains it subject to the same idle and background locks.
Automatic renewal runs only while unlocked. Creation and recovery require real Secure
Enclave hardware; the simulator has no software-key fallback.

Every profile domain is a username candidate. Publish the profile at each domain,
then verify it with the home DC and choose active usernames in Edit Profile.

The integration is isolated in [BlahIdentity](submodules/BlahIdentity),
[BlahIdentityUI](submodules/BlahIdentityUI), and the
[network adapter](submodules/TelegramCore/Sources/Network/BlahIdentityNetwork.swift).
[BlahDiem](https://github.com/UInt8Co/BlahDiem) and its native Diem crypto backend are
upstream Swift package dependencies. Their revisions live in
[Package.swift](build-system/SwiftPackages/Package.swift); the committed
[Package.resolved](build-system/SwiftPackages/Package.resolved) locks the transitive graph.
[MODULE.bazel](MODULE.bazel) imports the package products through
`rules_swift_package_manager` for both app builds and generated Xcode projects.
The current integration requires Swift 6.4; Xcode and Bazel versions are pinned in
`versions.json`. Signed-home connections use MTProtoKit until the alternative engine
supports the same device-proof binding and signed endpoint/RSA pin contract. Saved
authorizations are checked against the identity, device and cache namespace before
reconnecting; legacy slots without that binding require a fresh account slot.

To update a revision, edit the manifest, then regenerate both lockfiles:

```sh
swift package --package-path build-system/SwiftPackages resolve
build-input/bazel-9.2.0-darwin-arm64 mod deps
```

Recovery exports use BlahDiem’s `KeyFile` API and the platform PBKDF2 adapter; hardware
keys remain non-exportable.
The [package integration tests](build-system/SwiftPackages/Tests/BlahDiemPackageTests.swift)
exercise profile encoding and sealed-key recovery against the fetched packages:

```sh
swift test --package-path build-system/SwiftPackages

# Or through Bazel on macOS:
build-input/bazel-9.2.0-darwin-arm64 test //build-system/SwiftPackages:BlahDiemPackageTests \
  --apple_platform_type=macos --macos_minimum_os=15.0
```

The Apple backend uses the upstream Swift Crypto package, which delegates to CryptoKit
on Apple platforms. No WASM is linked into the native app. Build through the repository's
`build-system/Make/Make.py` workflow
with the configured Xcode and signing environment. Device validation must cover cancelled
biometric prompts, lock/background transitions, publication after signup, file recovery,
and iCloud recovery on a second device.

# Creating your Telegram Application

1. [**Obtain your own api_id**](https://core.telegram.org/api/obtaining_api_id) for your application.
2. Please **do not** use the name Telegram for your app — or make sure your users understand that it is unofficial.
3. Kindly **do not** use our standard logo (white paper plane in a blue circle) as your app's logo.
3. Please study our [**security guidelines**](https://core.telegram.org/mtproto/security_guidelines) and take good care of your users' data and privacy.
4. Please remember to publish **your** code too in order to comply with the licences.

# Quick Compilation Guide

## Get the Code

```
git clone --recursive -j8 https://github.com/TelegramMessenger/Telegram-iOS.git
```

## Setup Xcode

Install Xcode (directly from https://developer.apple.com/download/applications or using the App Store).

## Adjust Configuration

1. Generate a random identifier:
```
openssl rand -hex 8
```
2. Create a new Xcode project. Use `Telegram` as the Product Name. Use `org.{identifier from step 1}` as the Organization Identifier.
3. Open `Keychain Access` and navigate to `Certificates`. Locate `Apple Development: your@email.address (XXXXXXXXXX)` and double tap the certificate. Under `Details`, locate `Organizational Unit`. This is the Team ID.
4. Edit `build-system/template_minimal_development_configuration.json`. Use data from the previous steps.

## Generate an Xcode project

```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    generateProject \
    --configurationPath=build-system/template_minimal_development_configuration.json \
    --xcodeManagedCodesigning
```

# Advanced Compilation Guide

## Xcode

1. Copy and edit `build-system/appstore-configuration.json`.
2. Copy `build-system/fake-codesigning`. Create and download provisioning profiles, using the `profiles` folder as a reference for the entitlements.
3. Generate an Xcode project:
```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    generateProject \
    --configurationPath=configuration_from_step_1.json \
    --codesigningInformationPath=directory_from_step_2
```

## IPA

1. Repeat the steps from the previous section. Use distribution provisioning profiles.
2. Run:
```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    build \
    --configurationPath=...see previous section... \
    --codesigningInformationPath=...see previous section... \
    --buildNumber=100001 \
    --configuration=release_arm64
```

The app, extensions, and embedded iOS frameworks share the deployment target in
[Telegram/BUILD](Telegram/BUILD). Keep their generated `MinimumOSVersion` values aligned
with the compiled binaries.

# FAQ

## Xcode is stuck at "build-request.json not updated yet"

Occasionally, you might observe the following message in your build log:
```
"/Users/xxx/Library/Developer/Xcode/DerivedData/Telegram-xxx/Build/Intermediates.noindex/XCBuildData/xxx.xcbuilddata/build-request.json" not updated yet, waiting...
```

Should this occur, simply cancel the ongoing build and initiate a new one.

## Telegram_xcodeproj: no such package 

Following a system restart, the auto-generated Xcode project might encounter a build failure accompanied by this error:
```
ERROR: Skipping '@rules_xcodeproj_generated//generator/Telegram/Telegram_xcodeproj:Telegram_xcodeproj': no such package '@rules_xcodeproj_generated//generator/Telegram/Telegram_xcodeproj': BUILD file not found in directory 'generator/Telegram/Telegram_xcodeproj' of external repository @rules_xcodeproj_generated. Add a BUILD file to a directory to mark it as a package.
```

If you encounter this issue, re-run the project generation steps in the README.


# Tips

## Codesigning is not required for simulator-only builds

Add `--disableProvisioningProfiles`:
```
python3 build-system/Make/Make.py \
    --cacheDir="$HOME/telegram-bazel-cache" \
    generateProject \
    --configurationPath=path-to-configuration.json \
    --codesigningInformationPath=path-to-provisioning-data \
    --disableProvisioningProfiles
```

## Versions

Each release is built using a specific Xcode version (see `versions.json`). The helper script checks the versions of the installed software and reports an error if they don't match the ones specified in `versions.json`. It is possible to bypass these checks:

```
python3 build-system/Make/Make.py --overrideXcodeVersion build ... # Don't check the version of Xcode
```
