#!/usr/bin/env bash
# Real protected-file observation under independently provisioned Linux users.
# Ephemeral GitHub-hosted runner ONLY. Not a broker or SQLite VFS proof.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != 'true' || "${RUNNER_OS:-}" != 'Linux' ||
      "${RUNNER_ENVIRONMENT:-}" != 'github-hosted' || "$(id -u)" -eq 0 ]]; then
  printf '%s\n' 'E_POLICY_EPHEMERAL_NONROOT_RUNNER_REQUIRED' >&2
  exit 1
fi
sudo -n true
getent passwd jdc-authority >/dev/null
getent passwd jdc-mcp-client >/dev/null
[[ "$(id -u jdc-authority)" -gt 0 && "$(id -u jdc-mcp-client)" -gt 0 ]] || exit 1
[[ "$(id -u jdc-authority)" != "$(id -u jdc-mcp-client)" ]] || exit 1
command -v setpriv >/dev/null || exit 1
actual_nnp="$(sudo -n -u jdc-authority -- setpriv --no-new-privs -- awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)"
[[ "$actual_nnp" == '1' ]] || { printf '%s\n' 'E_POLICY_NO_NEW_PRIVS_NOT_PROVEN' >&2; exit 1; }
service_gid="$(id -g jdc-authority)"
fixture="native/authority-store/target/debug/examples/custody_fixture"
probe="native/authority-service/target/debug/examples/linux_epoch_anchor_probe"
[[ -x "$fixture" && -x "$probe" ]] || { printf '%s\n' 'E_POLICY_FIXTURE_MISSING' >&2; exit 1; }
directory='/etc/jdc-authority'
policy="${directory}/policy.sqlite3"
anchor="${directory}/policy-anchor"
alias="${directory}/policy-hardlink"
[[ ! -e "$directory" && ! -L "$directory" ]] || {
  printf '%s\n' 'E_POLICY_PREEXISTING_STATE' >&2
  exit 1
}
source_file="$(mktemp /tmp/jdc-policy-fixture.XXXXXXXX)"
source_anchor="$(mktemp /tmp/jdc-policy-anchor.XXXXXXXX)"
mismatch_anchor="$(mktemp /tmp/jdc-policy-mismatch.XXXXXXXX)"
cleanup() {
  local code=$?
  sudo -n rm -f -- "$alias" "$policy" "$anchor" || code=1
  sudo -n rmdir -- "$directory" || code=1
  rm -f -- "$source_file" "$source_anchor" "$mismatch_anchor" || code=1
  exit "$code"
}
trap cleanup EXIT
"$fixture" init-policy-bytes "$source_file"
"$fixture" write-policy-anchor "$source_anchor"
"$fixture" write-policy-anchor-mismatch "$mismatch_anchor"
[[ "$(wc -c < "$source_anchor")" -eq 40 && "$(wc -c < "$mismatch_anchor")" -eq 40 ]] || exit 1
[[ "$(stat -c '%s' -- "$source_file")" -ge 512 ]] || exit 1
sudo -n install -d -o root -g root -m 0755 -- "$directory"
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$policy"
[[ "$(sudo -n stat -c '%u:%g:%a:%h' -- "$policy")" == "0:${service_gid}:640:1" ]] || exit 1
before="$(sudo -n sha256sum -- "$policy" | cut -d' ' -f1)"
verdict() {
  local expected="$1"
  shift
  local actual
  actual="$("$@")" || { printf '%s\n' 'E_POLICY_PROBE_EXECUTION_FAILED' >&2; exit 1; }
  [[ "$actual" == "$expected" ]] || { printf '%s\n' 'E_POLICY_WRONG_VERDICT' >&2; exit 1; }
}
verdict CANDIDATE sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-candidate
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor" "$anchor"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot
verdict DENIED sudo -n -u jdc-mcp-client -- setpriv --no-new-privs -- "$probe" policy-deny
verdict DENIED sudo -n -- setpriv --no-new-privs -- "$probe" policy-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$mismatch_anchor" "$anchor"
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor" "$anchor"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot
sudo -n chmod 0660 -- "$policy"
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-deny
sudo -n chmod 0640 -- "$policy"
verdict CANDIDATE sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-candidate
sudo -n chown jdc-authority:jdc-authority -- "$policy"
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-deny
sudo -n chown root:jdc-authority -- "$policy"
verdict CANDIDATE sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-candidate
sudo -n ln -- "$policy" "$alias"
[[ "$(sudo -n stat -c '%h' -- "$policy")" == '2' ]] || exit 1
[[ "$(sudo -n stat -c '%d:%i' -- "$policy")" == "$(sudo -n stat -c '%d:%i' -- "$alias")" ]] || exit 1
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-deny
sudo -n rm -- "$alias"
verdict CANDIDATE sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-candidate
sudo -n truncate -s 40 -- "$policy"
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-deny
sudo -n rm -- "$policy"
sudo -n ln -s -- "$source_file" "$policy"
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-deny
sudo -n rm -- "$policy"
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$policy"
verdict CANDIDATE sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-candidate
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot
after="$(sudo -n sha256sum -- "$policy" | cut -d' ' -f1)"
[[ "$after" == "$before" ]] || { printf '%s\n' 'E_POLICY_FIXTURE_BYTES_CHANGED' >&2; exit 1; }
printf '%s\n' 'LINUX_ADMIN_POLICY_FILE_CUSTODY_PASS'
