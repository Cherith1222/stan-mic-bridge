#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[[ "$(uname -s)" == Darwin ]] || { echo 'Build on macOS.' >&2; exit 1; }
[[ $# -ge 1 && $# -le 2 ]] || { echo 'Usage: bash build-app.command OUTPUT_DIRECTORY [--universal]' >&2; exit 1; }
mkdir -p "$1"
output="$(cd "$1" && pwd)"
app="$output/Stan Mic Bridge.app"
[[ ! -e "$app" ]] || { echo 'Output app already exists; use a fresh directory.' >&2; exit 1; }
archs=("$(uname -m)")
if [[ "${2:-}" == --universal ]]; then archs=(x86_64 arm64); fi
if [[ $# == 2 && "$2" != --universal ]]; then echo 'Unknown build option.' >&2; exit 1; fi
temporary_root="${TMPDIR:-/tmp}"
stage="$(mktemp -d "${temporary_root%/}/stan-mic-compile.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources"
cp Info.plist "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
main_binaries=()
helper_binaries=()
broker_binaries=()
for arch in "${archs[@]}"; do
  case "$arch" in x86_64|arm64) ;; *) echo 'Unsupported architecture.' >&2; exit 1 ;; esac
  echo "Building $arch app and update helper…"
  xcrun swiftc -swift-version 5 -O -target "${arch}-apple-macosx12.0" \
    -framework AppKit -framework AVFoundation -framework Security -framework CryptoKit \
    StanMicBridge.swift LocalSigning.swift CredentialBrokerClient.swift CredentialBrokerProtocol.swift -o "$stage/StanMicBridge-$arch"
  xcrun swiftc -swift-version 5 -O -target "${arch}-apple-macosx12.0" \
    -framework AppKit -framework Security -framework CryptoKit \
    UpdateHelper.swift LocalSigning.swift LocalSigningTests.swift CredentialBrokerTests.swift CredentialBrokerClient.swift CredentialBrokerProtocol.swift -o "$stage/StanMicUpdater-$arch"
  xcrun swiftc -swift-version 5 -O -target "${arch}-apple-macosx12.0" \
    -framework Security -framework CryptoKit \
    CredentialBroker.swift CredentialBrokerProtocol.swift -o "$stage/StanMicCredentialBroker-$arch"
  main_binaries+=("$stage/StanMicBridge-$arch")
  helper_binaries+=("$stage/StanMicUpdater-$arch")
  broker_binaries+=("$stage/StanMicCredentialBroker-$arch")
done
xcrun lipo -create "${main_binaries[@]}" -output "$app/Contents/MacOS/StanMicBridge"
xcrun lipo -create "${helper_binaries[@]}" -output "$app/Contents/Helpers/StanMicUpdater"
xcrun lipo -create "${broker_binaries[@]}" -output "$app/Contents/Helpers/StanMicCredentialBroker"
echo 'Generating the application icon…'
xcrun swiftc -swift-version 5 -O -framework AppKit GenerateIcon.swift -o "$stage/GenerateIcon"
"$stage/GenerateIcon" "$stage/AppIcon.iconset"
iconutil --convert icns "$stage/AppIcon.iconset" --output "$app/Contents/Resources/AppIcon.icns"
[[ -s "$app/Contents/Resources/AppIcon.icns" ]]
# Normalize a separate signing input even when a source archive was converted
# by another platform. AMFI requires standard XML with LF line endings.
plutil -convert xml1 -o "$stage/AudioInput.entitlements" AudioInput.entitlements
plutil -lint "$stage/AudioInput.entitlements"
codesign --force --sign - --options runtime --identifier com.stan.micbridge.updater "$app/Contents/Helpers/StanMicUpdater"
codesign --force --sign - --options runtime --identifier com.stan.micbridge.credentials "$app/Contents/Helpers/StanMicCredentialBroker"
codesign --force --sign - --options runtime --entitlements "$stage/AudioInput.entitlements" --identifier com.stan.micbridge "$app"
codesign --verify --deep --strict --verbose=2 "$app"
echo "Built: $app"
