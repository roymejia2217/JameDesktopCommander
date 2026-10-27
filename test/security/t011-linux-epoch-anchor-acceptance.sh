#!/usr/bin/env bash
# Exact real-principal proof on a disposable GitHub-hosted Linux runner only.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_OS:-}" != "Linux" ||
      "${RUNNER_ENVIRONMENT:-}" != "github-hosted" || "$(id -u)" -eq 0 ]]; then
  printf '%s\n' 'E_ANCHOR_EPHEMERAL_NONROOT_RUNNER_REQUIRED' >&2
  exit 1
fi
sudo -n true
getent passwd jdc-authority >/dev/null
getent passwd jdc-mcp-client >/dev/null
service_gid="$(id -g jdc-authority)"
[[ "$service_gid" -gt 0 && "$(id -u jdc-authority)" -gt 0 ]] || exit 1
[[ "$(id -u jdc-authority)" != "$(id -u jdc-mcp-client)" ]] || exit 1

probe="native/authority-service/target/debug/examples/linux_epoch_anchor_probe"
[[ -x "$probe" ]] || { printf '%s\n' 'E_ANCHOR_PROBE_MISSING' >&2; exit 1; }
directory="/etc/jdc-authority"
anchor="${directory}/policy-anchor"
[[ ! -e "$directory" && ! -L "$directory" ]] || {
  printf '%s\n' 'E_ANCHOR_PREEXISTING_STATE' >&2
  exit 1
}
source_file="$(mktemp /tmp/jdc-anchor-fixture.XXXXXXXX)"
cleanup() {
  local result=$?
  sudo -n rm -f -- "$anchor" || result=1
  sudo -n rmdir -- "$directory" || result=1
  rm -f -- "$source_file" || result=1
  exit "$result"
}
trap cleanup EXIT
printf '\x00\x00\x00\x00\x00\x00\x00\x01' > "$source_file"
for _ in {1..32}; do printf '\xA5' >> "$source_file"; done
[[ "$(wc -c < "$source_file")" -eq 40 ]] || exit 1
sudo -n install -d -o root -g root -m 0755 -- "$directory"
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$anchor"
[[ "$(sudo -n stat -c '%u:%g:%a' -- "$anchor")" == "0:${service_gid}:640" ]] || exit 1
before="$(sudo -n sha256sum -- "$anchor" | cut -d' ' -f1)"

expect_verdict() {
  local expected="$1"
  shift
  local actual
  actual="$("$@")" || { printf '%s\n' 'E_ANCHOR_PROBE_EXECUTION_FAILED' >&2; exit 1; }
  [[ "$actual" == "$expected" ]] || {
    printf '%s\n' 'E_ANCHOR_WRONG_VERDICT' >&2
    exit 1
  }
}
expect_verdict MATCH sudo -n -u jdc-authority -- "$probe" match
expect_verdict DENIED sudo -n -u jdc-mcp-client -- "$probe" deny
expect_verdict DENIED sudo -n -- "$probe" deny

sudo -n chmod 0660 -- "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- "$probe" deny
sudo -n chmod 0640 -- "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- "$probe" match

sudo -n chown jdc-authority:jdc-authority -- "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- "$probe" deny
sudo -n chown root:jdc-authority -- "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- "$probe" match

sudo -n truncate -s 39 -- "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- "$probe" deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- "$probe" match

sudo -n rm -- "$anchor"
sudo -n ln -s -- "$source_file" "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- "$probe" deny
sudo -n rm -- "$anchor"
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- "$probe" match
after="$(sudo -n sha256sum -- "$anchor" | cut -d' ' -f1)"
[[ "$after" == "$before" ]] || {
  printf '%s\n' 'E_ANCHOR_CANONICAL_BYTES_CHANGED' >&2
  exit 1
}
printf '%s\n' 'LINUX_EPOCH_ANCHOR_REAL_PRINCIPALS_PASS'
