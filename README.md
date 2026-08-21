# INTTI Patcher

The original app ships as split APKs (base + `config.arm64_v8a`) with a native `libil2cpp.so` containing its ad and paywall logic. This tool merges the splits, patches the native binary in-place, rewrites the manifest, and signs the result.

## Features

- **Two input modes**
  - **APK pair**: pick `com.OneGlitch.INTTI.apk` + `config.arm64_v8a.apk`
  - **XAPK**: pick the complete `.xapk`; base and split are extracted automatically
- **SHA-256 verification**: refuses to patch anything but the exact supported version, so you never get a silently broken APK
- **Merged single APK output**: the patched result is one standard, installable APK
- **Optional package rename**: install the patched copy alongside the original

## Installation

1. Download and install the [latest release](https://github.com/trimpsuz/intti-patcher/releases/latest) of the patcher.
2. Download the INTTI app v1.12.0 xapk, for example [from APKPure](https://apkpure.com/intti-tj-pelit-ruokalistat/com.OneGlitch.INTTI/download).
3. Open the patcher, patch and install the INTTI app.

## What the patch does

- Removes all ads (interstitial, rewarded, banner)
- Removes the paywalls (all premium features are unlocked)

## Requirements

- Android 7.0+ (API 24+)
- Original **INTTI 1.12.0 (version code 300011)** as either:
  - `com.OneGlitch.INTTI.apk` + `config.arm64_v8a.apk`, or
  - the complete `.xapk`

## Usage

1. Install the patcher APK and open **INTTI Patcher**.
2. Choose the input mode and pick your files.
3. _(Optional)_ Enter a new package name to keep both apps installed.
4. Tap **Patch and save APK**, takes a minute or two, then the installer opens automatically.
5. Install:
   - Without a new package name: **uninstall the original first** (signatures differ).
   - With a new package name: just install, the original stays.
6. If the install prompt is blocked, allow "Install unknown apps" for INTTI Patcher in Settings.

> The patched APK is stored temporarily in the app's private storage. It is replaced on the next patch and removed if the app is uninstalled or the storage is cleared.

## Building from source

Prerequisites: JDK 17 and the Android SDK (platform 34, build-tools 34.0.0).

```bash
git clone https://github.com/trimpsuz/intti-patcher
cd intti-patcher
./gradlew assembleRelease
# output: app/build/outputs/apk/release/app-release.apk
```

## License

This project is licensed under GPLv3. See the [LICENSE](LICENSE) file for more details.
