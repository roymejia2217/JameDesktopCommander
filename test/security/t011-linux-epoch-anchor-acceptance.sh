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
if ! command -v setpriv >/dev/null; then
  printf '%s\n' 'E_ANCHOR_SETPRIV_UNAVAILABLE' >&2
  exit 1
fi
# POSITIVE control must prove the real Linux thread attribute required by
# verify_service_identity; a direct sudo -u launch would be a false negative.
service_nnp="$(sudo -n -u jdc-authority -- setpriv --no-new-privs -- awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)"
if [[ "$service_nnp" != '1' ]]; then
  printf '%s\n' 'E_ANCHOR_NO_NEW_PRIVS_NOT_PROVEN' >&2
  exit 1
fi

probe="native/authority-service/target/debug/examples/linux_epoch_anchor_probe"
[[ -x "$probe" ]] || { printf '%s\n' 'E_ANCHOR_PROBE_MISSING' >&2; exit 1; }
directory="/etc/jdc-authority"
anchor="${directory}/policy-anchor"
hardlink_alias="${directory}/policy-anchor-hardlink"
[[ ! -e "$directory" && ! -L "$directory" ]] || {
  printf '%s\n' 'E_ANCHOR_PREEXISTING_STATE' >&2
  exit 1
}
source_file="$(mktemp /tmp/jdc-anchor-fixture.XXXXXXXX)"
cleanup() {
  local result=$?
  sudo -n rm -f -- "$hardlink_alias" || result=1
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
expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" match
expect_verdict DENIED sudo -n -u jdc-mcp-client -- setpriv --no-new-privs -- "$probe" deny
expect_verdict DENIED sudo -n -- setpriv --no-new-privs -- "$probe" deny

sudo -n chmod 0660 -- "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" deny
sudo -n chmod 0640 -- "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" match

sudo -n chown jdc-authority:jdc-authority -- "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" deny
sudo -n chown root:jdc-authority -- "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" match

sudo -n truncate -s 39 -- "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" match

sudo -n rm -- "$anchor"
sudo -n ln -s -- "$source_file" "$anchor"
expect_verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" deny
sudo -n rm -- "$anchor"
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$anchor"
expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" match

# Reject a real same-inode alias even when root legitimately created it.
# A file-name-only check could falsely accept this witness; kernel nlink must deny.
sudo -n ln -- "$anchor" "$hardlink_alias"
if [[ "$(sudo -n stat -c '%h' -- "$anchor")" != '2' ||
      "$(sudo -n stat -c '%d:%i' -- "$anchor")" != "$(sudo -n stat -c '%d:%i' -- "$hardlink_alias")" ]]; then
  printf '%s\n' 'E_ANCHOR_HARDLINK_OBJECT_NOT_PROVEN' >&2
  exit 1
fi
expect_verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" deny
sudo -n rm -- "$hardlink_alias"
[[ "$(sudo -n stat -c '%h' -- "$anchor")" == '1' ]] || {
  printf '%s\n' 'E_ANCHOR_HARDLINK_OBJECT_NOT_RESTORED' >&2
  exit 1
}
expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" match
after="$(sudo -n sha256sum -- "$anchor" | cut -d' ' -f1)"
[[ "$after" == "$before" ]] || {
  printf '%s\n' 'E_ANCHOR_CANONICAL_BYTES_CHANGED' >&2
  exit 1
}
printf '%s\n' 'LINUX_EPOCH_ANCHOR_REAL_PRINCIPALS_PASS'
