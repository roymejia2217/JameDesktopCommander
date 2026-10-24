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
cleanup() {
  if [[ -n "$active_server_pid" ]]; then
    kill "$active_server_pid" 2>/dev/null || :
    wait "$active_server_pid" 2>/dev/null || :
  fi
  rm -f -- "$sandbox"/case-*.sock
  rmdir -- "$sandbox" || :
}
trap cleanup EXIT
# Attacker can traverse, not create/replace entries in the runner-owned dir.
chmod 0711 -- "$sandbox"

run_case() {
  local label="$1" principal="$2" expected="$3" uid="$4" gid="$5" verdict="$6"
  local socket="$sandbox/case-$label.sock" ready='' result='' fd
  coproc JDC_PEER { "$fixture" serve "$socket" "$expected"; }
  active_server_pid="$JDC_PEER_PID"
  fd="${JDC_PEER[0]}"
  if ! IFS= read -r -t 8 ready <&"$fd" || [[ "$ready" != "READY" ]]; then
    printf '%s\n' 'E_PEER_SERVER_NOT_READY' >&2
    return 1
  fi
  # Fixture-only socket access; authentication must reject based on SO_PEERCRED.
  chmod 0777 -- "$socket"
  if [[ "$principal" == "runner" ]]; then
    "$fixture" client "$socket" 'claim:root:allow=true'
  else
    sudo -n -u nobody -- "$fixture" client "$socket" "claim:$approved:allow=true"
  fi
  if ! IFS= read -r -t 8 result <&"$fd"; then
    printf '%s\n' 'E_PEER_SERVER_NO_VERDICT' >&2
    return 1
  fi
  printf 'K' >&"${JDC_PEER[1]}"
  wait "$active_server_pid"
  active_server_pid=''
  if [[ ! "$result" =~ ^OBSERVED\ uid=([0-9]+)\ gid=([0-9]+)\ pid=([0-9]+)\ verdict=(MATCH|DENIED)$ ]]; then
    printf '%s\n' 'E_PEER_UNEXPECTED_OBSERVATION' >&2; return 1
  fi
  if [[ "${BASH_REMATCH[1]}" != "$uid" || "${BASH_REMATCH[2]}" != "$gid" ||
        "${BASH_REMATCH[3]}" -le 0 || "${BASH_REMATCH[3]}" -eq "$$" ||
        "${BASH_REMATCH[4]}" != "$verdict" ]]; then
    printf '%s\n' 'E_PEER_IDENTITY_VERDICT_MISMATCH' >&2; return 1
  fi
  rm -f -- "$socket"
}

run_case approved runner "$approved" "$approved_uid" "$approved_gid" MATCH
run_case foreign nobody "$approved" "$other_uid" "$other_gid" DENIED
run_case foreign-positive nobody nobody "$other_uid" "$other_gid" MATCH
run_case runner-foreign runner nobody "$approved_uid" "$approved_gid" DENIED
printf '%s\n' 'T011_CONNECTED_PEER_CROSS_PRINCIPAL_PASS'
