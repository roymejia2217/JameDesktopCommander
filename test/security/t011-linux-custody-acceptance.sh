#!/usr/bin/env bash
# CI-only cross-principal acceptance fixture. NEVER invoke on a live host.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_OS:-}" != "Linux" || "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]]; then
  printf '%s\n' 'E_CUSTODY_EPHEMERAL_RUNNER_REQUIRED' >&2
  exit 1
fi
if [[ "$(id -u)" -eq 0 ]]; then
  printf '%s\n' 'E_CUSTODY_RUNNER_MUST_NOT_BE_ROOT' >&2
  exit 1
fi
if ! getent passwd jdc-authority >/dev/null || ! getent group jdc-authority >/dev/null; then
  printf '%s\n' 'E_CUSTODY_SERVICE_PRINCIPAL_NOT_PROVISIONED' >&2
  exit 1
fi
if ! getent passwd nobody >/dev/null; then
  printf '%s\n' 'E_CUSTODY_NO_ATTACKER_PRINCIPAL' >&2
  exit 1
fi
sudo -n true
# Account is provisioned by official systemd-sysusers in the governed CI job.
# Verify effective account contract rather than recreating a lookalike user.
if [[ "$(getent passwd jdc-authority | cut -d: -f7)" != "/usr/sbin/nologin" ]]; then
  printf '%s\n' 'E_CUSTODY_SERVICE_LOGIN_SHELL_MISMATCH' >&2
  exit 1
fi
if [[ "$(id -gn jdc-authority)" != "jdc-authority" ]]; then
  printf '%s\n' 'E_CUSTODY_SERVICE_PRIMARY_GROUP_MISMATCH' >&2
  exit 1
fi

service_uid="$(id -u jdc-authority)"
attacker_uid="$(id -u nobody)"
attacker_group="$(id -gn nobody)"
if [[ "$service_uid" -eq 0 || "$attacker_uid" -eq 0 || "$service_uid" -eq "$attacker_uid" ]]; then
  printf '%s\n' 'E_CUSTODY_PRINCIPALS_NOT_ISOLATED' >&2
  exit 1
fi

identity_probe="native/authority-service/target/debug/examples/identity_probe"
store_fixture="native/authority-store/target/debug/examples/custody_fixture"
[[ -x "$identity_probe" && -x "$store_fixture" ]] || {
  printf '%s\n' 'E_CUSTODY_BINARIES_MISSING' >&2
  exit 1
}

fixture_dir="$(mktemp -d /tmp/jdc-t011-custody.XXXXXXXX)"
database="$fixture_dir/policy.sqlite3"
snapshot="$(mktemp /tmp/jdc-t011-replay.XXXXXXXX)"
canary="$(mktemp /tmp/jdc-t011-canary.XXXXXXXX)"
# All fixtures are under /tmp on a disposable GitHub-hosted runner, never
# under $HOME or a production state directory. The runner is auto-destroyed.
sudo -n chown jdc-authority:jdc-authority "$fixture_dir"
sudo -n chmod 0700 "$fixture_dir"
sudo -n chown nobody:"$attacker_group" "$canary"

# Positive identity MUST run with the exact NNP kernel requirement used by
# the protected systemd service. Never weaken the Rust identity preflight.
if ! command -v setpriv >/dev/null; then
  printf '%s\n' 'E_CUSTODY_SETPRIV_UNAVAILABLE' >&2
  exit 1
fi
service_nnp="$(sudo -n -u jdc-authority -- setpriv --no-new-privs -- awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)"
if [[ "$service_nnp" != '1' ]]; then
  printf '%s\n' 'E_CUSTODY_NO_NEW_PRIVS_NOT_PROVEN' >&2
  exit 1
fi
if ! sudo -n -u jdc-authority -- setpriv --no-new-privs -- "$identity_probe"; then
  printf '%s\n' 'E_CUSTODY_DEDICATED_IDENTITY_POSITIVE_FAILED' >&2
  exit 1
fi

# Adversarial REAL token: same service UID and primary GID, but a foreign
# supplementary group injected by the disposable runner administrator.
# The proof must show the intended UID/groups were actually installed
# before it can credit the identity probe with rejecting them.
service_gid="$(id -g jdc-authority)"
attacker_gid="$(id -g nobody)"
if [[ "$service_gid" -eq "$attacker_gid" || "$attacker_gid" -eq 0 ]]; then
  printf '%s\n' 'E_CUSTODY_GROUPS_NOT_DISTINCT' >&2
  exit 1
fi
identity_uid="$(sudo -n setpriv --reuid "$service_uid" --regid "$service_gid" --groups "$service_gid,$attacker_gid" --no-new-privs -- id -u)"
identity_groups="$(sudo -n setpriv --reuid "$service_uid" --regid "$service_gid" --groups "$service_gid,$attacker_gid" --no-new-privs -- id -G)"
# Verify real/effective/saved credentials independently via Linux procfs.
# Otherwise an unrelated UID mismatch could masquerade as group rejection.
uid_triplet="$(sudo -n setpriv --reuid "$service_uid" --regid "$service_gid" --groups "$service_gid,$attacker_gid" --no-new-privs -- awk '/^Uid:/ {print $2, $3, $4}' /proc/self/status)"
gid_triplet="$(sudo -n setpriv --reuid "$service_uid" --regid "$service_gid" --groups "$service_gid,$attacker_gid" --no-new-privs -- awk '/^Gid:/ {print $2, $3, $4}' /proc/self/status)"
identity_nnp="$(sudo -n setpriv --reuid "$service_uid" --regid "$service_gid" --groups "$service_gid,$attacker_gid" --no-new-privs -- awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)"
if [[ "$identity_uid" != "$service_uid" || " $identity_groups " != *" $attacker_gid "* ||
      "$uid_triplet" != "$service_uid $service_uid $service_uid" ||
      "$gid_triplet" != "$service_gid $service_gid $service_gid" ||
      "$identity_nnp" != '1' ]]; then
  printf '%s\n' 'E_CUSTODY_GROUP_INJECTION_NOT_PROVEN' >&2
  exit 1
fi
if sudo -n setpriv --reuid "$service_uid" --regid "$service_gid" --groups "$service_gid,$attacker_gid" --no-new-privs -- "$identity_probe"; then
  printf '%s\n' 'E_CUSTODY_SUPPLEMENTARY_GROUP_ACCEPTED' >&2
  exit 1
fi
if sudo -n -u nobody -- setpriv --no-new-privs -- "$identity_probe"; then
  printf '%s\n' 'E_CUSTODY_IDENTITY_SPOOF' >&2
  exit 1
fi
sudo -n -u nobody -- touch "$canary"
sudo -n -u nobody -- test -w "$canary"
# Positive control: the attacker identity really can create a hard link in
# attacker-owned storage. Otherwise denial could be a broken runner/filesystem.
attacker_link="${canary}.hardlink"
sudo -n -u nobody -- ln "$canary" "$attacker_link"
if [[ "$(stat -c '%d:%i' "$canary")" != "$(stat -c '%d:%i' "$attacker_link")" ]]; then
  printf '%s\n' 'E_CUSTODY_POSITIVE_HARDLINK_WRONG_OBJECT' >&2
  exit 1
fi
sudo -n -u nobody -- rm "$attacker_link"
sudo -n -u jdc-authority -- "$store_fixture" init "$database"
sudo -n -u jdc-authority -- chmod 0600 "$database"
if [[ "$(sudo -n -u jdc-authority -- stat -c '%a' "$database")" != "600" ]]; then
  printf '%s\n' 'E_CUSTODY_STATE_FILE_PERMISSIONS' >&2
  exit 1
fi

# An older, internally valid database is provided to the attacker on purpose.
# It cannot replace the protected owner's newer database without directory
# permissions, even if the contents of the old snapshot are known.
sudo -n install -m 0600 -o nobody -g "$attacker_group" "$database" "$snapshot"
sudo -n -u jdc-authority -- "$store_fixture" advance "$database"
# SQLite itself must create and remove a DELETE-mode rollback journal.
sudo -n -u jdc-authority -- "$store_fixture" prove-rollback-journal "$database"
sudo -n -u jdc-authority -- "$store_fixture" verify-2 "$database"
expected_hash="$(sudo -n -u jdc-authority -- sha256sum "$database")"

expect_denied() {
  local operation="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'E_CUSTODY_UNAUTHORIZED_%s\n' "$operation" >&2
    exit 1
  fi
}
expect_denied identity sudo -n -u nobody -- setpriv --no-new-privs -- "$identity_probe"
expect_denied browse sudo -n -u nobody -- ls -la "$fixture_dir"
expect_denied read sudo -n -u nobody -- cat "$database"
expect_denied write sudo -n -u nobody -- touch "$database"
expect_denied create sudo -n -u nobody -- mkdir "$fixture_dir/forged"
expect_denied overwrite sudo -n -u nobody -- cp "$snapshot" "$database"
expect_denied rename sudo -n -u nobody -- mv "$database" "$fixture_dir/renamed.sqlite3"
expect_denied unlink sudo -n -u nobody -- rm "$database"
expect_denied replay sudo -n -u nobody -- mv "$snapshot" "$database"
# Verify the actual protected directory's ownership of all SQLite auxiliary
# namespaces. WAL/SHM cases are namespace probes, not active WAL tests.
for suffix in -journal -wal -shm; do
  sidecar="${database}${suffix}"
  sudo -n -u jdc-authority -- touch "$sidecar"
  sudo -n -u jdc-authority -- test -f "$sidecar"
  expect_denied sidecar_read sudo -n -u nobody -- cat "$sidecar"
  expect_denied sidecar_write sudo -n -u nobody -- touch "$sidecar"
  sudo -n -u jdc-authority -- rm "$sidecar"
  expect_denied sidecar_create sudo -n -u nobody -- touch "$sidecar"
  if [[ -e "$sidecar" ]]; then
    printf '%s\n' 'E_CUSTODY_UNAUTHORIZED_SIDECAR_CREATED' >&2
    exit 1
  fi
done
expect_denied parent_rename sudo -n -u nobody -- mv "$fixture_dir" "${fixture_dir}-replaced"
expect_denied parent_chmod sudo -n -u nobody -- chmod 0777 "$fixture_dir"
# Both hard-link directions must be denied under independent OS principals.
# This is a protected-domain claim, NOT a same-principal hard-link solution.
expect_denied hardlink_source sudo -n -u nobody -- ln "$database" "${canary}.protected-alias"
expect_denied hardlink_destination sudo -n -u nobody -- ln "$canary" "$fixture_dir/forged-hardlink"
if [[ -e "${canary}.protected-alias" ]] ||
    sudo -n -u jdc-authority -- test -e "$fixture_dir/forged-hardlink"; then
  printf '%s\n' 'E_CUSTODY_HARDLINK_ALIAS_CREATED' >&2
  exit 1
fi

# Test the actual prepublication staging namespace, not merely SQLite
# state. A same-volume owner positive link MUST work before an attacker
# denial can establish separate-principal custody of this stage object.
# The file remains unpublished throughout the proof.
stage_file="$(sudo -n -u jdc-authority -- mktemp "$fixture_dir/.jdc-stage.XXXXXXXX")"
sudo -n -u jdc-authority -- sh -c 'printf %s STAGED_PRIVATE_BYTES > "$1"' sh "$stage_file"
stage_hash="$(sudo -n -u jdc-authority -- sha256sum "$stage_file" | cut -d ' ' -f1)"
owner_stage_link="${stage_file}.owner-link"
sudo -n -u jdc-authority -- ln -- "$stage_file" "$owner_stage_link"
stage_object_id="$(sudo -n -u jdc-authority -- stat -c '%d:%i' -- "$stage_file")"
owner_link_id="$(sudo -n -u jdc-authority -- stat -c '%d:%i' -- "$owner_stage_link")"
if [[ "$stage_object_id" != "$owner_link_id" ]]; then
  printf '%s\n' 'E_CUSTODY_STAGE_OWNER_LINK_IDENTITY' >&2
  exit 1
fi
echo 'STAGE_OWNER_LINK_IDENTITY_PROVEN'
sudo -n -u jdc-authority -- rm -- "$owner_stage_link"
stage_exterior_alias="${canary}.stage-alias"
expect_denied STAGE_ATTACKER_CAN_READ sudo -n -u nobody -- cat -- "$stage_file"
expect_denied STAGE_ATTACKER_CAN_HARDLINK sudo -n -u nobody -- ln -- "$stage_file" "$stage_exterior_alias"
expect_denied STAGE_ATTACKER_CAN_APPEND sudo -n -u nobody -- sh -c 'printf X >> "$1"' sh "$stage_file"
expect_denied STAGE_ATTACKER_CAN_REMOVE sudo -n -u nobody -- rm -- "$stage_file"
expect_denied STAGE_ATTACKER_CAN_CREATE sudo -n -u nobody -- touch -- "${stage_file}.forged"
if [[ -e "$stage_exterior_alias" || -e "${stage_file}.forged" ]]; then
  printf '%s\n' 'E_CUSTODY_STAGE_ALIAS_APPEARED' >&2
  exit 1
fi
if [[ "$(sudo -n -u jdc-authority -- sha256sum "$stage_file" | cut -d ' ' -f1)" != "$stage_hash" ]]; then
  printf '%s\n' 'E_CUSTODY_STAGE_BYTES_CHANGED' >&2
  exit 1
fi
sudo -n -u jdc-authority -- rm -- "$stage_file"
echo 'T011_STAGE_LINUX_CUSTODY_PASS_NONRELEASE'

actual_hash="$(sudo -n -u jdc-authority -- sha256sum "$database")"
if [[ "$actual_hash" != "$expected_hash" ]]; then
  printf '%s\n' 'E_CUSTODY_UNAUTHORIZED_BYTES_CHANGED' >&2
  exit 1
fi
sudo -n -u jdc-authority -- "$store_fixture" verify-2 "$database"
printf '%s\n' 'T011-C4i Linux distinct-principal custody: PASS (non-release)'
