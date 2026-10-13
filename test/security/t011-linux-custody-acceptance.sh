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
if getent passwd jdc-authority >/dev/null; then
  printf '%s\n' 'E_CUSTODY_UNEXPECTED_EXISTING_SERVICE_PRINCIPAL' >&2
  exit 1
fi
if ! getent passwd nobody >/dev/null; then
  printf '%s\n' 'E_CUSTODY_NO_ATTACKER_PRINCIPAL' >&2
  exit 1
fi
sudo -n true
sudo -n useradd --system --user-group --no-create-home --shell /usr/sbin/nologin jdc-authority

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

# PROVE both identities can actually execute commands; do not misinterpret
# a broken sudo invocation as protection.
sudo -n -u jdc-authority -- "$identity_probe"
if sudo -n -u nobody -- "$identity_probe"; then
  printf '%s\n' 'E_CUSTODY_IDENTITY_SPOOF' >&2
  exit 1
fi
sudo -n -u nobody -- touch "$canary"
sudo -n -u nobody -- test -w "$canary"
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
expect_denied identity sudo -n -u nobody -- "$identity_probe"
expect_denied browse sudo -n -u nobody -- ls -la "$fixture_dir"
expect_denied read sudo -n -u nobody -- cat "$database"
expect_denied write sudo -n -u nobody -- touch "$database"
expect_denied create sudo -n -u nobody -- mkdir "$fixture_dir/forged"
expect_denied overwrite sudo -n -u nobody -- cp "$snapshot" "$database"
expect_denied rename sudo -n -u nobody -- mv "$database" "$fixture_dir/renamed.sqlite3"
expect_denied unlink sudo -n -u nobody -- rm "$database"
expect_denied replay sudo -n -u nobody -- mv "$snapshot" "$database"
expect_denied parent_rename sudo -n -u nobody -- mv "$fixture_dir" "${fixture_dir}-replaced"
expect_denied parent_chmod sudo -n -u nobody -- chmod 0777 "$fixture_dir"

actual_hash="$(sudo -n -u jdc-authority -- sha256sum "$database")"
if [[ "$actual_hash" != "$expected_hash" ]]; then
  printf '%s\n' 'E_CUSTODY_UNAUTHORIZED_BYTES_CHANGED' >&2
  exit 1
fi
sudo -n -u jdc-authority -- "$store_fixture" verify-2 "$database"
printf '%s\n' 'T011-C4i Linux distinct-principal custody: PASS (non-release)'
