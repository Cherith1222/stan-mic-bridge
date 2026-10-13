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
temporary_root="${TMPDIR:-/tmp}"
stage="$(mktemp -d "${temporary_root%/}/stan-mic-build.XXXXXX")"
app="$stage/Stan Mic Bridge.app"
applications_dir="$HOME/Applications"
destination="$applications_dir/Stan Mic Bridge.app"
backup=''
cleanup_install() {
  result=$?
  trap - EXIT
  if (( result != 0 )); then
    if [[ -n "$backup" && -d "$backup" && ! -e "$destination" && ! -L "$destination" ]]; then
      mv "$backup" "$destination" || echo "Previous app remains at: $backup" >&2
    fi
    if [[ -e "$app/Contents/Resources/CredentialBrokerPin.json" || -L "$app/Contents/Resources/CredentialBrokerPin.json" ]]; then
      recovery="$applications_dir/Stan Mic Bridge.install-recovery.app"
      if [[ -d "$applications_dir" && ! -L "$applications_dir" && ! -e "$recovery" && ! -L "$recovery" ]] && mv "$app" "$recovery"; then
        if codesign --verify --deep --strict "$recovery"; then
          echo "Installation was interrupted. Signature-verified pin recovery retained at: $recovery" >&2
          echo 'To recover, quit Stan Mic Bridge. Preserve any app currently in ~/Applications under a backup name, then move this retained app to ~/Applications/Stan Mic Bridge.app using Finder.' >&2
          echo 'Then rerun this trusted source installer with --local-signing. Recovery bundles are never adopted automatically.' >&2
        else
          echo "Installation was interrupted. Staged files retained for repair at: $recovery" >&2
          echo 'Signature verification failed. Do not install these retained files; preserve them for repair.' >&2
        fi
      else
        echo "Installation was interrupted. Keep the staging folder for credential-pin recovery: $stage" >&2
        exit "$result"
      fi
    fi
  fi
  rm -rf -- "$stage"
  exit "$result"
}
trap cleanup_install EXIT
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
  echo 'This source-installer run establishes the sealed credential-broker pin; older in-app updaters cannot perform this first migration.'
  echo "Setting up or reusing this Mac's fixed signing identity and sealed credential-broker pin. macOS may ask for Keychain approval."
  "$signer" --setup-local-signing "$app"
else
  # Preserve an existing local identity even when the flag is omitted on a later install.
  "$signer" --prepare-local-signing "$app" "$destination"
fi
codesign --verify --deep --strict "$app"
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
