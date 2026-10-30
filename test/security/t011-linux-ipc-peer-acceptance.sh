#!/usr/bin/env bash
# Disposable-runner-only connected AF_UNIX cross-principal identity proof.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_OS:-}" != "Linux" ||
      "${RUNNER_ENVIRONMENT:-}" != "github-hosted" || "$(id -u)" -eq 0 ]]; then
  printf '%s\n' 'E_PEER_EPHEMERAL_RUNNER_REQUIRED' >&2
  exit 1
fi
sudo -n true
getent passwd nobody >/dev/null
fixture="native/authority-service/target/debug/examples/peer_identity_acceptance"
[[ -x "$fixture" ]] || { printf '%s\n' 'E_PEER_FIXTURE_MISSING' >&2; exit 1; }
approved="$(id -un)"
approved_uid="$(id -u)"
approved_gid="$(id -g)"
other_uid="$(id -u nobody)"
other_gid="$(id -g nobody)"
[[ "$approved_uid" -gt 0 && "$approved_gid" -gt 0 &&
   "$other_uid" -gt 0 && "$other_gid" -gt 0 &&
   "$other_uid" != "$approved_uid" ]] || {
  printf '%s\n' 'E_PEER_DISTINCT_PRINCIPALS_REQUIRED' >&2; exit 1;
}
sandbox="$(mktemp -d /tmp/jdc-t011-peer.XXXXXXXX)"
[[ "$sandbox" == /tmp/jdc-t011-peer.* ]] || exit 1
active_server_pid=''
attacker_dir=''
cleanup() {
  if [[ -n "$active_server_pid" ]]; then
    kill "$active_server_pid" 2>/dev/null || :
    wait "$active_server_pid" 2>/dev/null || :
  fi
  rm -f -- "$sandbox"/case-*.sock
  rmdir -- "$sandbox" || :
  if [[ -n "${attacker_dir:-}" ]]; then
    sudo -n -u nobody -- rm -f -- "$attacker_dir/positive-control" || :
    sudo -n -u nobody -- rmdir -- "$attacker_dir" || :
  fi
}
trap cleanup EXIT
# Runner-owned disposable parent models protected endpoint name custody.
# This does NOT prove the future installed service directory/ACL is safe.
# Attacker can traverse, but cannot create/replace names in this directory.
chmod 0711 -- "$sandbox"
# Positive control: this exact attacker principal can create filesystem names
# in its own directory; an unrelated sudo failure must never count as denial.
attacker_dir="$(sudo -n -u nobody -- mktemp -d /tmp/jdc-t011-peer-attacker.XXXXXXXX)"
[[ "$attacker_dir" == /tmp/jdc-t011-peer-attacker.* &&
   "$(stat -c '%u' "$attacker_dir")" == "$other_uid" ]] || {
  printf '%s\n' 'E_PEER_ATTACKER_STORAGE_UNAVAILABLE' >&2; exit 1;
}
sudo -n -u nobody -- ln -s "$sandbox" "$attacker_dir/positive-control"
# The 0700 attacker-owned directory is intentionally opaque to the runner.
# Inspect this positive control under the same unprivileged OS identity.
sudo -n -u nobody -- test -L "$attacker_dir/positive-control"
sudo -n -u nobody -- rm -- "$attacker_dir/positive-control"

run_case() {
  local label="$1" principal="$2" expected="$3" uid="$4" gid="$5" verdict="$6"
  local protocol="${7:-peer}" server_mode='serve' client_mode='client'
  case "$protocol" in
    peer) ;;
    c4d) server_mode='serve-c4d'; client_mode='client-c4d' ;;
    c4d-invalid) server_mode='serve-c4d'; client_mode='client-c4d-invalid' ;;
    *) printf '%s\n' 'E_PEER_UNKNOWN_FIXTURE_PROTOCOL' >&2; return 1 ;;
  esac
  local socket="$sandbox/case-$label.sock" ready='' result='' fd
  # Test runner independently supplies the expected kernel UID/GID. The Rust
  # server compares these internally and never emits raw identities into logs.
  coproc JDC_PEER { "$fixture" "$server_mode" "$socket" "$expected" "$uid" "$gid"; }
  active_server_pid="$JDC_PEER_PID"
  fd="${JDC_PEER[0]}"
  if ! IFS= read -r -t 8 ready <&"$fd" || [[ "$ready" != "READY" ]]; then
    printf '%s\n' 'E_PEER_SERVER_NOT_READY' >&2
    return 1
  fi
  # Intentionally permissive *test socket*: connect is allowed, but peer
  # identity must still decide matching. This is not a production ACL.
  [[ -S "$socket" ]] || { printf '%s\n' 'E_PEER_SOCKET_MISSING' >&2; return 1; }
  chmod 0777 -- "$socket"
  local socket_identity
  socket_identity="$(stat -c '%d:%i' "$socket")"
  # The attacker can traverse the parent but may neither unlink the existing
  # listener nor replace an absent sibling with its own symlink.
  if sudo -n -u nobody -- rm -- "$socket" >/dev/null 2>&1 ||
     sudo -n -u nobody -- ln -s "$attacker_dir" "$socket.forged" >/dev/null 2>&1; then
    printf '%s\n' 'E_PEER_UNTRUSTED_SOCKET_NAMESPACE_MUTATION' >&2; return 1
  fi
  if [[ ! -S "$socket" || "$(stat -c '%d:%i' "$socket")" != "$socket_identity" ||
        -e "$socket.forged" || -L "$socket.forged" ]]; then
    printf '%s\n' 'E_PEER_SOCKET_OBJECT_CHANGED' >&2; return 1
  fi
  if [[ "$principal" == "runner" ]]; then
    "$fixture" "$client_mode" "$socket" 'claim:root:allow=true'
  else
    sudo -n -u nobody -- "$fixture" "$client_mode" "$socket" "claim:$approved:allow=true"
  fi
  if ! IFS= read -r -t 8 result <&"$fd"; then
    printf '%s\n' 'E_PEER_SERVER_NO_VERDICT' >&2
    return 1
  fi
  printf 'K' >&"${JDC_PEER[1]}"
  wait "$active_server_pid"
  active_server_pid=''
  local observed=''
  if [[ "$protocol" == peer ]]; then
    if [[ ! "$result" =~ ^OBSERVED_VERIFIED\ verdict=(MATCH|DENIED)$ ]]; then
      printf '%s\n' 'E_PEER_UNEXPECTED_OBSERVATION' >&2; return 1
    fi
  else
    if [[ ! "$result" =~ ^OBSERVED_C4D\ verdict=(ACCEPT|DENIED)$ ]]; then
      printf '%s\n' 'E_C4D_UNEXPECTED_OBSERVATION' >&2; return 1
    fi
  fi
  observed="${BASH_REMATCH[1]}"
  if [[ "$observed" != "$verdict" ]]; then
    printf '%s\n' 'E_PEER_IDENTITY_VERDICT_MISMATCH' >&2; return 1
  fi
  rm -f -- "$socket"
}

run_case approved runner "$approved" "$approved_uid" "$approved_gid" MATCH
run_case foreign nobody "$approved" "$other_uid" "$other_gid" DENIED
run_case foreign-positive nobody nobody "$other_uid" "$other_gid" MATCH
run_case runner-foreign runner nobody "$approved_uid" "$approved_gid" DENIED

# Run the identical true kernel-principal matrix with one canonical C4d frame.
# No claimed client name is used to choose the expected UID/GID.
run_case c4d-approved runner "$approved" "$approved_uid" "$approved_gid" ACCEPT c4d
run_case c4d-foreign foreign "$approved" "$approved_uid" "$approved_gid" DENIED c4d
run_case c4d-foreign-positive foreign nobody "$other_uid" "$other_gid" ACCEPT c4d
run_case c4d-runner-foreign runner nobody "$other_uid" "$other_gid" DENIED c4d
run_case c4d-malformed runner "$approved" "$approved_uid" "$approved_gid" DENIED c4d-invalid
printf '%s\n' 'T011_CONNECTED_PEER_AND_C4D_CROSS_PRINCIPAL_PASS'
