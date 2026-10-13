#!/bin/bash
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
# Load the real trap without executing the installer or touching user state.
cleanup_source="$(sed -n '/^cleanup_install() {$/,/^}$/p' "$script_dir/install.command")"
[[ -n "$cleanup_source" ]] || { echo 'Installer cleanup function not found.' >&2; exit 1; }
eval "$cleanup_source"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/stan-mic-recovery-test.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
for scenario in restore occupied; do
  applications_dir="$fixture/$scenario/Applications"
  mkdir -p "$applications_dir"
  stage="$fixture/$scenario/stage"
  app="$stage/Stan Mic Bridge.app"
  destination="$applications_dir/Stan Mic Bridge.app"
  backup="$applications_dir/previous.app"
  recovery="$applications_dir/Stan Mic Bridge.install-recovery.app"
  mkdir -p "$app/Contents/Resources" "$backup"
  printf 'synthetic-pin' > "$app/Contents/Resources/CredentialBrokerPin.json"
  printf 'old-app' > "$backup/old-marker"
  if [[ "$scenario" == occupied ]]; then
    mkdir -p "$recovery"
    printf 'existing-recovery' > "$recovery/preserve-marker"
  fi
  status=0
  (trap cleanup_install EXIT; exit 37) || status=$?
  [[ "$status" == 37 ]]
  [[ -f "$destination/old-marker" && ! -e "$backup" ]]
  if [[ "$scenario" == restore ]]; then
    [[ -f "$recovery/Contents/Resources/CredentialBrokerPin.json" && ! -e "$stage" ]]
  else
    [[ "$(cat "$recovery/preserve-marker")" == existing-recovery ]]
    [[ -f "$app/Contents/Resources/CredentialBrokerPin.json" ]]
  fi
done
echo 'Installer recovery: old app restored, sealed pin retained, occupied recovery untouched, failure status preserved.'
