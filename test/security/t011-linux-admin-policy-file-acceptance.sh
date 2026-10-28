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
publisher="native/authority-service/target/debug/examples/linux_admin_publication_probe"
[[ -x "$fixture" && -x "$probe" && -x "$publisher" ]] || { printf '%s\n' 'E_POLICY_FIXTURE_MISSING' >&2; exit 1; }
directory='/etc/jdc-authority'
policy="${directory}/policy.sqlite3"
anchor="${directory}/policy-anchor"
alias="${directory}/policy-hardlink"
publish_intent="${directory}/.policy-publish-inflight"
[[ ! -e "$directory" && ! -L "$directory" ]] || {
  printf '%s\n' 'E_POLICY_PREEXISTING_STATE' >&2
  exit 1
}
source_file="$(mktemp /tmp/jdc-policy-fixture.XXXXXXXX)"
source_anchor="$(mktemp /tmp/jdc-policy-anchor.XXXXXXXX)"
mismatch_anchor="$(mktemp /tmp/jdc-policy-mismatch.XXXXXXXX)"
source_file_v2="$(mktemp /tmp/jdc-policy-v2.XXXXXXXX)"
source_anchor_v2="$(mktemp /tmp/jdc-policy-witness-v2.XXXXXXXX)"
source_file_v3="$(mktemp /tmp/jdc-policy-v3.XXXXXXXX)"
source_anchor_v3="$(mktemp /tmp/jdc-policy-witness-v3.XXXXXXXX)"
cleanup() {
  local code=$?
  sudo -n rm -f -- "$alias" "$policy" "$anchor" "$publish_intent" "${directory}/.policy-next.sqlite3" "${directory}/.policy-next-anchor" "${policy}-journal" "${policy}-wal" "${policy}-shm" || code=1
  sudo -n rmdir -- "$directory" || code=1
  rm -f -- "$source_file" "$source_anchor" "$mismatch_anchor" "$source_file_v2" "$source_anchor_v2" "$source_file_v3" "$source_anchor_v3" || code=1
  exit "$code"
}
trap cleanup EXIT
"$fixture" init-policy-bytes "$source_file"
"$fixture" write-policy-anchor "$source_anchor"
"$fixture" write-policy-anchor-mismatch "$mismatch_anchor"
"$fixture" init-policy-bytes-v2 "$source_file_v2"
"$fixture" write-policy-anchor-v2 "$source_anchor_v2"
"$fixture" init-policy-bytes-v3 "$source_file_v3"
"$fixture" write-policy-anchor-v3 "$source_anchor_v3"
[[ "$(wc -c < "$source_anchor")" -eq 40 && "$(wc -c < "$mismatch_anchor")" -eq 40 && "$(wc -c < "$source_anchor_v2")" -eq 40 ]] || exit 1
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

# Hot SQLite sidecars are never silently ignored when parsing an isolated
# main DB image. Root owns the protected parent; service has read-only access.
for entry in journal wal shm; do
  sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor" "${policy}-${entry}"
  case "$entry" in
    journal) printf '%s\n' 'E_POLICY_JOURNAL_SIDECAR_DENIED' ;;
    wal) printf '%s\n' 'E_POLICY_WAL_SIDECAR_DENIED' ;;
    shm) printf '%s\n' 'E_POLICY_SHM_SIDECAR_DENIED' ;;
  esac
  verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
  sudo -n rm -- "${policy}-${entry}"
  verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot
done
sudo -n ln -s -- "$source_file" "${policy}-journal"
printf '%s\n' 'E_POLICY_SYMLINK_SIDECAR_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n rm -- "${policy}-journal"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot

# A root-admin publication marker prohibits reading even a coherent DB +
# witness. The less privileged service must not be capable of creating it.
if sudo -n -u jdc-authority -- setpriv --no-new-privs -- touch "$publish_intent" 2>/dev/null; then
  printf '%s\n' 'E_POLICY_UNPRIVILEGED_CREATED_ADMIN_MARKER' >&2
  exit 1
fi
printf '%s\n' 'E_POLICY_PUBLISH_UNPRIVILEGED_CREATE_DENIED'
if sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$publisher" begin 2>/dev/null; then
  printf '%s\n' 'E_POLICY_UNPRIVILEGED_BEGAN_PUBLISH' >&2
  exit 1
fi
verdict PUBLISH_INTENT_CREATED sudo -n -- "$publisher" begin
[[ "$(sudo -n stat -c '%u:%g:%a:%h:%s' -- "$publish_intent")" == '0:0:600:1:0' ]] || exit 1
printf '%s\n' 'E_POLICY_PUBLISH_INTENT_CREATED'
if sudo -n -- "$publisher" begin 2>/dev/null; then
  printf '%s\n' 'E_POLICY_DUPLICATE_PUBLISH_ALLOWED' >&2
  exit 1
fi
printf '%s\n' 'E_POLICY_PUBLISH_DOUBLE_BEGIN_DENIED'
printf '%s\n' 'E_POLICY_PUBLISH_INTENT_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n rm -- "$publish_intent"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot
sudo -n ln -s -- "$source_file" "$publish_intent"
printf '%s\n' 'E_POLICY_PUBLISH_SYMLINK_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n rm -- "$publish_intent"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot

# The same OS-authenticated service process must observe a stable policy,
# deny a root-controlled transition, and remain denied after restoration.
# The coprocess pipes provide deterministic event-driven handshakes:
# no clocks, polling loops, or path inputs are sent to the native observer.
coproc POLICY_MON {
  sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-monitor-stdin
}
monitor_pid="$POLICY_MON_PID"
read -r -t 10 monitor_line <&"${POLICY_MON[0]}" || {
  printf '%s\n' 'E_POLICY_MONITOR_START_TIMEOUT' >&2
  exit 1
}
[[ "$monitor_line" == 'MONITOR_READY' ]] || exit 1
printf 'check\n' >&"${POLICY_MON[1]}"
read -r -t 10 monitor_line <&"${POLICY_MON[0]}" || exit 1
[[ "$monitor_line" == 'MONITOR_MATCH' ]] || exit 1

sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file_v2" "$policy"
printf 'check\n' >&"${POLICY_MON[1]}"
read -r -t 10 monitor_line <&"${POLICY_MON[0]}" || exit 1
[[ "$monitor_line" == 'MONITOR_DENIED' ]] || exit 1

sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$policy"
printf 'check\n' >&"${POLICY_MON[1]}"
read -r -t 10 monitor_line <&"${POLICY_MON[0]}" || exit 1
[[ "$monitor_line" == 'MONITOR_DENIED' ]] || exit 1
wait "$monitor_pid" || exit 1
printf '%s\n' 'E_POLICY_MONITOR_STICKY_DENIAL'
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot

# Adversarial policy-publish ordering matrix. These are deliberate
# administrator simulations on an ephemeral test runner, NOT a publisher:
# install(1) is not an atomic durable update or a service implementation.
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file_v2" "$policy"
printf '%s\n' 'E_POLICY_FORWARD_POLICY_WITH_STALE_WITNESS'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$policy"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot

sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor_v2" "$anchor"
printf '%s\n' 'E_POLICY_FORWARD_WITNESS_WITH_STALE_POLICY'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file_v2" "$policy"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-v2

sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file" "$policy"
printf '%s\n' 'E_POLICY_ROLLBACK_DB_ONLY'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor" "$anchor"
# NEGATIVE security proof: an administrator able to restore BOTH sources
# defeats an entirely local epoch/digest equality check. Never claim a
# hardware-backed or external monotonic authority from this acceptance.
printf '%s\n' 'E_POLICY_FULL_STATE_ROLLBACK_IS_UNDETECTABLE'
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot
# Real root-only two-phase publication. Source is an ephemeral CI-created
# SQLite image, never a client-supplied policy path in the service.
verdict PUBLISH_INTENT_CREATED sudo -n -- "$publisher" begin
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny

# Stale exclusive staging file from an interrupted attempt must fail closed.
sudo -n install -o root -g root -m 0600 -- "$source_anchor" "${directory}/.policy-next.sqlite3"
if sudo -n -- "$publisher" commit-v2 "$source_file_v2" 2>/dev/null; then
  printf '%s\n' 'E_POLICY_STALE_STAGE_WAS_OVERWRITTEN' >&2
  exit 1
fi
printf '%s\n' 'E_POLICY_STALE_STAGE_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n rm -- "${directory}/.policy-next.sqlite3"
verdict PUBLISH_COMMITTED sudo -n -- "$publisher" commit-v2 "$source_file_v2"
[[ ! -e "$publish_intent" && ! -L "$publish_intent" ]] || exit 1
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-v2
printf '%s\n' 'E_POLICY_FORWARD_PUBLISH_COMMITTED'

# Forward-only: an attempted downgrade is refused, and the durable
# intent stays present until an independently trusted admin recovers.
verdict PUBLISH_INTENT_CREATED sudo -n -- "$publisher" begin
if sudo -n -- "$publisher" commit-v2 "$source_file" 2>/dev/null; then
  printf '%s\n' 'E_POLICY_BACKWARD_PUBLISH_ACCEPTED' >&2
  exit 1
fi
printf '%s\n' 'E_POLICY_BACKWARD_PUBLISH_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
# CI-only independent root cleanup of the rejected intent; the Rust
# production candidate deliberately offers no automatic repair operation.
sudo -n rm -- "$publish_intent"
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-v2
# Recovery acceptance: admin intent persists after a simulated interrupted
# policy rename. No automatic repair and no rollback to a lower epoch.
verdict PUBLISH_INTENT_CREATED sudo -n -- "$publisher" begin
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor_v3" "${directory}/.policy-next-anchor"
if sudo -n -- "$publisher" recover-split 2>/dev/null; then
  printf '%s\n' 'E_RECOVER_STALE_POLICY_ACCEPTED' >&2
  exit 1
fi
printf '%s\n' 'E_RECOVER_STALE_POLICY_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor_v2" "${directory}/.policy-next-anchor"
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_file_v3" "$policy"
if sudo -n -- "$publisher" recover-split 2>/dev/null; then
  printf '%s\n' 'E_RECOVER_UNMATCHED_ANCHOR_ACCEPTED' >&2
  exit 1
fi
printf '%s\n' 'E_RECOVER_UNMATCHED_ANCHOR_DENIED'
verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-deny

# Only the strictly forward, exactly matching stage can complete the
# interrupted rename. No blanket intent removal is available.
sudo -n install -o root -g jdc-authority -m 0640 -- "$source_anchor_v3" "${directory}/.policy-next-anchor"
verdict PUBLISH_SPLIT_RECOVERED sudo -n -- "$publisher" recover-split
[[ ! -e "$publish_intent" && ! -e "${directory}/.policy-next-anchor" ]] || exit 1
verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$probe" policy-snapshot-v3
printf '%s\n' 'E_RECOVER_SPLIT_POLICY_TO_V3_SUCCESS'
printf '%s\n' 'LINUX_ADMIN_POLICY_FILE_CUSTODY_PASS'
