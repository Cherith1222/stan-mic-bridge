#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --local-signing ) ]]; then
  echo 'Usage: bash install.command [--local-signing]' >&2
  exit 1
fi
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
destination="$HOME/Applications/Stan Mic Bridge.app"
if [[ -L "$HOME/Applications" || -L "$destination" ]]; then
  echo 'Installation directory or app must not be a symbolic link.' >&2
  exit 1
fi
mkdir -p "$HOME/Applications"
bash build-app.command "$stage"
# Run a separate helper copy so signing the app never rewrites executing code.
signer="$stage/StanMicSigningHelper"
cp "$app/Contents/Helpers/StanMicUpdater" "$signer"
codesign --verify --strict "$signer"
if [[ "${1:-}" == --local-signing ]]; then
  echo "Setting up or reusing this Mac's fixed signing identity. macOS may ask for Keychain approval."
  "$signer" --setup-local-signing "$app"
else
  # Preserve an existing local identity even when the flag is omitted on a later install.
  "$signer" --prepare-local-signing "$app" "$destination"
fi
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
