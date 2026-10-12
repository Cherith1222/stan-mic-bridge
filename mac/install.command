#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'This installer must run on your Mac.' >&2
  exit 1
fi
major="$(sw_vers -productVersion | cut -d. -f1)"
if (( major < 12 )); then
  echo 'Stan Mic Bridge requires macOS 12 or newer.' >&2
  exit 1
fi
if ! xcrun --find swiftc >/dev/null 2>&1; then
  echo 'Apple Command Line Tools are required. Run: xcode-select --install'
  echo 'Complete the Apple installer, then run this installer again.'
  exit 2
fi
if pgrep -x StanMicBridge >/dev/null; then
  echo 'Choose Quit from the existing Stan Mic Bridge menu, then run this installer again.' >&2
  exit 3
fi
stage="$(mktemp -d "${TMPDIR:-/tmp}/stan-mic-build.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
app="$stage/Stan Mic Bridge.app"
mkdir -p "$app/Contents/MacOS" "$HOME/Applications"
cp Info.plist "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
arch="$(uname -m)"
case "$arch" in arm64|x86_64) ;; *) echo 'Unsupported Mac architecture.' >&2; exit 1 ;; esac
echo 'Building the native menu bar app with Apple Swift…'
xcrun swiftc -swift-version 5 -O -target "${arch}-apple-macosx12.0" \
  -framework AppKit -framework AVFoundation -framework Security \
  StanMicBridge.swift -o "$app/Contents/MacOS/StanMicBridge"
codesign --force --sign - --identifier com.stan.micbridge "$app"
codesign --verify --strict --verbose=2 "$app"
destination="$HOME/Applications/Stan Mic Bridge.app"
if [[ -e "$destination" ]]; then
  backup="$HOME/Applications/Stan Mic Bridge.backup.$(date +%Y%m%d-%H%M%S).app"
  [[ ! -e "$backup" ]] || { echo 'Backup already exists; try again later.' >&2; exit 1; }
  mv "$destination" "$backup"
  echo "Previous app preserved at: $backup"
fi
mv "$app" "$destination"
open "$destination"
echo 'Installed. Look for Mic in the Mac menu bar.'
echo 'Configure with your existing private HTTPS link, then choose Start and allow microphone access.'
echo 'Chrome and this Terminal window can close after the app opens.'
