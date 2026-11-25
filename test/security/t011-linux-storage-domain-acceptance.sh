#!/usr/bin/env bash
# T011 #148: disposable Linux mount/device isolation proof. NON-RELEASE.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted || "$(id -u)" -eq 0 ]]; then
  echo 'E_STORAGE_DOMAIN_HOSTED_LINUX_REQUIRED' >&2
  exit 1
fi
command -v mountpoint >/dev/null
command -v findmnt >/dev/null
command -v setpriv >/dev/null
getent passwd jdc-authority >/dev/null
getent passwd nobody >/dev/null
getent passwd jdc-mcp-client >/dev/null
sudo -n true
service_uid="$(id -u jdc-authority)"
service_gid="$(id -g jdc-authority)"
attacker_uid="$(id -u nobody)"
client_uid="$(id -u jdc-mcp-client)"
client_gid="$(id -g jdc-mcp-client)"
[[ "$service_uid" -ne 0 && "$attacker_uid" -ne 0 && "$client_uid" -ne 0 &&
   "$service_uid" -ne "$attacker_uid" && "$service_uid" -ne "$client_uid" &&
   "$client_uid" -ne "$attacker_uid" && "$service_gid" -ne "$client_gid" ]] || exit 1
base="$(mktemp -d /tmp/jdc-t011-storage.XXXXXXXX)"
isolated="$base/service-volume"
attacker="$base/attacker-owned"
bind_alias=''
peer_server_pid=''
peer_server_log=''
mkdir -- "$isolated" "$attacker"
chmod 0711 "$base"
# The mountpoint's immediate parent belongs to the trusted administrator,
# not to the service or the attacker. Without this, a same-principal process
# could rename the mountpoint despite the isolated volume's own 0700 mode.
sudo -n chown root:root "$base"
sudo -n chown nobody:"$(id -gn nobody)" "$attacker"
sudo -n chmod 0700 "$attacker"
cleanup() {
  local code=$?
  trap - EXIT
  if [[ -n "$peer_server_pid" ]]; then
    kill "$peer_server_pid" 2>/dev/null || :
    wait "$peer_server_pid" 2>/dev/null || :
  fi
  if [[ -n "$peer_server_log" ]]; then
    # Preserve failing native-service diagnostics in the CI job log before
    # removing ephemeral files. A failed client test must never erase the
    # server-side denial/error evidence needed to distinguish transport and
    # authorization failures.
    if [[ "$code" -ne 0 && -f "$peer_server_log" ]]; then
      cat -- "$peer_server_log" >&2
    fi
    rm -f -- "$peer_server_log" || code=1
  fi
  if [[ -n "$bind_alias" ]] && findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null; then
    sudo -n umount -- "$bind_alias" || code=1
  fi
  if mountpoint -q "$isolated"; then
    sudo -n umount -- "$isolated" || code=1
  fi
  if [[ -n "$bind_alias" ]] && findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null; then
    echo 'E_STORAGE_CLEANUP_BIND_MOUNT_ACTIVE' >&2; exit 1
  fi
  if mountpoint -q "$isolated"; then
    echo 'E_STORAGE_CLEANUP_VOLUME_ACTIVE' >&2; exit 1
  fi
  [[ "$base" == /tmp/jdc-t011-storage.* ]] || exit 1
  sudo -n rm -rf -- "$base" || code=1
  exit "$code"
}
trap cleanup EXIT
# The real kernel must supply a separate mount device. Never fake an
# isolated root by putting two directories on the same filesystem.
sudo -n mount -t tmpfs -o "size=8m,mode=0700,uid=$service_uid,gid=$service_gid" tmpfs "$isolated"
mountpoint -q "$isolated"
[[ "$(stat -c %d "$isolated")" != "$(stat -c %d "$attacker")" ]] || {
  echo 'E_STORAGE_DOMAIN_SAME_DEVICE' >&2; exit 1;
}
[[ "$(stat -c %u:%g:%a "$isolated")" == "$service_uid:$service_gid:700" ]] || exit 1
service_file="$isolated/service.bin"
outside_file="$attacker/outside.bin"
sudo -n -u jdc-authority -- sh -c 'printf SERVICE_DOMAIN_BYTES > "$1"' sh "$service_file"
sudo -n -u nobody -- sh -c 'printf OUTSIDE_DOMAIN_SENTINEL_UNCHANGED > "$1"' sh "$outside_file"
outside_hash="$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)"

# This fixture verifies actual OS custody and kernel I/O only.
# Native root admission is tracked separately; do not credit it here.

# Exercise real read, in-place rewrite, append, rename and unlink under
# BOTH valid principals. Without these positive controls, an unavailable
# executable or broken filesystem could make all adversarial denials look green.
attacker_control="$attacker/operation-control.bin"
attacker_source="$attacker/operation-source.bin"
sudo -n -u nobody -- sh -c 'printf ATTACKER_CONTROL > "$1"' sh "$attacker_control"
sudo -n -u nobody -- sh -c 'printf ATTACKER_REPLACEMENT > "$1"' sh "$attacker_source"
sudo -n -u nobody -- cat -- "$attacker_control" >/dev/null
sudo -n -u nobody -- sh -c 'printf APPENDED >> "$1"' sh "$attacker_control"
sudo -n -u nobody -- cp -- "$attacker_source" "$attacker_control"
[[ "$(sudo -n -u nobody -- cat -- "$attacker_control")" == ATTACKER_REPLACEMENT ]] || exit 1
sudo -n -u nobody -- mv -- "$attacker_control" "$attacker/operation-renamed.bin"
sudo -n -u nobody -- rm -- "$attacker/operation-renamed.bin"
service_control="$isolated/service-control.bin"
sudo -n -u jdc-authority -- cp -- "$service_file" "$service_control"
sudo -n -u jdc-authority -- cat -- "$service_control" >/dev/null
sudo -n -u jdc-authority -- sh -c 'printf APPENDED >> "$1"' sh "$service_control"
sudo -n -u jdc-authority -- cp -- "$service_file" "$service_control"
sudo -n -u jdc-authority -- mv -- "$service_control" "$isolated/service-renamed.bin"
sudo -n -u jdc-authority -- rm -- "$isolated/service-renamed.bin"
[[ "$(sudo -n -u jdc-authority -- cat -- "$service_file")" == SERVICE_DOMAIN_BYTES ]] || exit 1
service_hash="$(sudo -n -u jdc-authority -- sha256sum "$service_file" | cut -d ' ' -f1)"
service_object_id="$(sudo -n stat -c '%d:%i' -- "$service_file")"
echo 'T011_STORAGE_REAL_OPERATION_POSITIVE_CONTROLS_PASS'

expect_denied() {
  local operation="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "E_STORAGE_UNAUTHORIZED_$operation" >&2
    exit 1
  fi
}
expect_denied read sudo -n -u nobody -- cat -- "$service_file"
expect_denied rewrite sudo -n -u nobody -- sh -c 'printf INJECTED > "$1"' sh "$service_file"
expect_denied append sudo -n -u nobody -- sh -c 'printf INJECTED >> "$1"' sh "$service_file"
expect_denied rename sudo -n -u nobody -- mv -- "$service_file" "$attacker/stolen-service.bin"
expect_denied unlink sudo -n -u nobody -- rm -- "$service_file"
expect_denied create sudo -n -u nobody -- touch -- "$isolated/injected.bin"
[[ ! -e "$attacker/stolen-service.bin" && ! -e "$isolated/injected.bin" ]] || {
  echo 'E_STORAGE_PROTECTED_NAMESPACE_CHANGED' >&2; exit 1;
}
[[ "$(sudo -n -u jdc-authority -- sha256sum "$service_file" | cut -d ' ' -f1)" == "$service_hash" ]] || {
  echo 'E_STORAGE_PROTECTED_BYTES_CHANGED' >&2; exit 1;
}
[[ "$(sudo -n stat -c '%d:%i' -- "$service_file")" == "$service_object_id" ]] || {
  echo 'E_STORAGE_PROTECTED_FILE_OBJECT_CHANGED' >&2; exit 1;
}
[[ "$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)" == "$outside_hash" ]] || {
  echo 'E_STORAGE_EXTERIOR_BYTES_CHANGED' >&2; exit 1;
}
echo 'T011_STORAGE_LINUX_READ_REWRITE_APPEND_RENAME_DENIED'

# The attack principal MUST succeed at a same-device hard link first.
sudo -n -u nobody -- ln -- "$outside_file" "$attacker/positive-link.bin"
[[ "$(sudo -n stat -c %d:%i "$outside_file")" == "$(sudo -n stat -c %d:%i "$attacker/positive-link.bin")" ]] || exit 1
sudo -n -u nobody -- rm -- "$attacker/positive-link.bin"
echo 'T011_STORAGE_SAME_VOLUME_HARDLINK_PASS'
# An unprivileged attacker must not enter the service-owned domain.
if sudo -n -u nobody -- ln -- "$outside_file" "$isolated/attacker.bin" 2>/dev/null; then
  echo 'E_STORAGE_ATTACKER_CROSSED_SERVICE_DOMAIN' >&2; exit 1
fi
# Even root cannot create a hard link across these actual mount devices.
# Verify EXDEV specifically so an unrelated permission failure cannot pass.
error="$(sudo -n env LC_ALL=C ln -- "$outside_file" "$isolated/admin-attempt.bin" 2>&1)" && {
  echo 'E_STORAGE_CROSS_VOLUME_HARDLINK_ALLOWED' >&2; exit 1;
}
grep -Fq 'Invalid cross-device link' <<< "$error" || {
  echo "E_STORAGE_WRONG_HARDLINK_FAILURE: $error" >&2; exit 1;
}
if sudo -n env LC_ALL=C ln -- "$service_file" "$attacker/reverse.bin" 2>/dev/null; then
  echo 'E_STORAGE_REVERSE_LINK_ALLOWED' >&2; exit 1
fi
[[ ! -e "$isolated/attacker.bin" && ! -e "$isolated/admin-attempt.bin" &&
   ! -e "$attacker/reverse.bin" ]] || exit 1
echo 'T011_STORAGE_CROSS_VOLUME_HARDLINK_DENIED'
# Separate filesystems do not prove object provenance when an administrator
# can import a foreign inode through a bind mount. This is a privileged
# counterexample, NOT an unprivileged attacker bypass or product acceptance.
sudo -n -u nobody -- chmod 0644 "$outside_file"
if sudo -n -u jdc-authority -- cat "$outside_file" >/dev/null 2>&1; then
  echo 'E_STORAGE_SERVICE_CAN_READ_PRIVATE_OUTSIDE_PATH' >&2; exit 1
fi
bind_alias="$isolated/admin-import.bin"
sudo -n -u jdc-authority -- sh -c ': > "$1"' sh "$bind_alias"
sudo -n mount --bind "$outside_file" "$bind_alias"
findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null || {
  echo 'E_STORAGE_BIND_MOUNT_NOT_ESTABLISHED' >&2; exit 1;
}
[[ "$(sudo -n stat -c %d:%i "$outside_file")" == "$(sudo -n stat -c %d:%i "$bind_alias")" ]] || {
  echo 'E_STORAGE_BIND_ALIAS_OBJECT_IDENTITY_MISMATCH' >&2; exit 1;
}
[[ "$(sudo -n -u jdc-authority -- cat "$bind_alias")" == OUTSIDE_DOMAIN_SENTINEL_UNCHANGED ]] || {
  echo 'E_STORAGE_BIND_ALIAS_SERVICE_CANNOT_READ_EXTERIOR' >&2; exit 1;
}
echo 'T011_STORAGE_ADMIN_BIND_ALIAS_EXPOSES_OUTSIDE_OBJECT_NONRELEASE'
# The bind alias is another mount path, not a hard link. A link-count
# postcheck alone therefore cannot distinguish this imported file object.
[[ "$(sudo -n stat -c %h "$outside_file")" == 1 &&
   "$(sudo -n stat -c %h "$bind_alias")" == 1 ]] || {
  echo 'E_STORAGE_BIND_ALIAS_UNEXPECTED_LINK_COUNT' >&2; exit 1;
}
# Exercise the kernel's openat2 NO_XDEV policy on an FD for the *already
# opened* authorized directory. Verify a real positive read and EXDEV for
# the imported alias. Never accept unrelated permission failures as EXDEV.
probe_source="$(realpath -e native/authority-service/target/debug/examples/linux_openat2_mount_probe)"
[[ -f "$probe_source" && -x "$probe_source" ]] || {
  echo 'E_STORAGE_OPENAT2_PROBE_MISSING' >&2; exit 1;
}
# The fixture service identity cannot necessarily traverse a CI checkout.
# Install the exact compiled probe inside its own isolated, service-owned
# volume and require byte-for-byte provenance before executing it.
probe_path="$isolated/linux_openat2_mount_probe"
sudo -n install -o jdc-authority -g jdc-authority -m 0500 -- "$probe_source" "$probe_path"
probe_hash="$(sha256sum "$probe_source" | cut -d ' ' -f1)"
[[ "$(sudo -n sha256sum "$probe_path" | cut -d ' ' -f1)" == "$probe_hash" ]] || {
  echo 'E_STORAGE_OPENAT2_PROBE_HASH_MISMATCH' >&2; exit 1;
}
sudo -n -u jdc-authority -- "$probe_path" "$isolated" service.bin allow
# Test a REAL pre-existing same-device hard link whose other pathname is
# outside a narrower authorized root. Keep exact outside bytes immutable.
# This cannot prove protection from a link created concurrently with a read.
read_scope="$isolated/read-scope"
outside_read="$isolated/outside-read-sentinel.bin"
sudo -n -u jdc-authority -- mkdir -- "$read_scope"
sudo -n -u jdc-authority -- cp -- "$service_file" "$read_scope/inside.bin"
sudo -n -u jdc-authority -- sh -c 'printf OUTSIDE_READ_SENTINEL_UNCHANGED > "$1"' sh "$outside_read"
outside_read_hash="$(sudo -n -u jdc-authority -- sha256sum "$outside_read" | cut -d ' ' -f1)"
sudo -n -u jdc-authority -- ln -- "$outside_read" "$read_scope/inside-hardlink.bin"
[[ "$(sudo -n stat -c '%d:%i' "$outside_read")" == \
   "$(sudo -n stat -c '%d:%i' "$read_scope/inside-hardlink.bin")" ]] || {
  echo 'E_STORAGE_PREEXISTING_HARDLINK_IDENTITY_MISMATCH' >&2; exit 1;
}
[[ "$(sudo -n stat -c %h "$outside_read")" == 2 ]] || exit 1
# Negative control: ordinary OS I/O through the hard-link pathname DOES
# expose the outside sentinel. Otherwise a failing fixture could look secure.
[[ "$(sudo -n -u jdc-authority -- cat -- "$read_scope/inside-hardlink.bin")" == OUTSIDE_READ_SENTINEL_UNCHANGED ]] || {
  echo 'E_STORAGE_HARDLINK_ATTACK_PRECONDITION_NOT_REPRODUCED' >&2; exit 1;
}
sudo -n -u jdc-authority -- "$probe_path" "$read_scope" inside.bin allow
sudo -n -u jdc-authority -- "$probe_path" "$read_scope" inside-hardlink.bin deny
[[ "$(sudo -n -u jdc-authority -- sha256sum "$outside_read" | cut -d ' ' -f1)" == "$outside_read_hash" ]] || {
  echo 'E_STORAGE_PREEXISTING_HARDLINK_OUTSIDE_BYTES_CHANGED' >&2; exit 1;
}
sudo -n -u jdc-authority -- rm -- "$read_scope/inside-hardlink.bin"
sudo -n -u jdc-authority -- "$probe_path" "$read_scope" inside.bin allow
echo 'T011_STORAGE_PREEXISTING_MULTILINK_READ_DENIED_NONRELEASE'
# The same production-compiled native read primitive must reject hostile
# objects and oversized payloads, not merely show syscall error codes.
sudo -n -u jdc-authority -- ln -s service.bin "$isolated/blocked-link.bin"
sudo -n -u jdc-authority -- ln -s "$outside_file" "$isolated/blocked-external-link.bin"
sudo -n -u jdc-authority -- mkdir "$isolated/blocked-directory"
sudo -n -u jdc-authority -- mkfifo "$isolated/blocked-fifo"
sudo -n -u jdc-authority -- truncate --size=1048576 "$isolated/at-limit.bin"
sudo -n -u jdc-authority -- truncate --size=1048577 "$isolated/too-large.bin"
sudo -n -u jdc-authority -- "$probe_path" "$isolated" at-limit.bin allow-limit
sudo -n -u jdc-authority -- "$probe_path" "$isolated" blocked-link.bin deny
sudo -n -u jdc-authority -- "$probe_path" "$isolated" blocked-external-link.bin deny
sudo -n -u jdc-authority -- "$probe_path" "$isolated" blocked-directory deny
sudo -n -u jdc-authority -- "$probe_path" "$isolated" blocked-fifo deny
sudo -n -u jdc-authority -- "$probe_path" "$isolated" too-large.bin deny
sudo -n -u jdc-authority -- "$probe_path" "$isolated" missing-file.bin deny
sudo -n -u jdc-authority -- "$probe_path" "$isolated" admin-import.bin deny-exdev
echo 'T011_STORAGE_BOUND_READ_REAL_KERNEL_PASS_NONRELEASE'
echo 'T011_STORAGE_OPENAT2_NO_XDEV_DENIES_BIND_ALIAS_NONRELEASE'
# Native test executable, not a production listener or user-host daemon.
# The existing isolated volume and real OS users are mandatory positive controls.
peer_source="$(realpath -e native/authority-service/target/debug/examples/linux_peered_read_proof)"
[[ -x "$peer_source" ]] || { echo 'E_PEER_PROOF_BINARY_MISSING' >&2; exit 1; }
peer_binary="$base/peered-read-proof"
sudo -n install -o root -g root -m 0555 -- "$peer_source" "$peer_binary"
[[ "$(sha256sum "$peer_source" | cut -d ' ' -f1)" == \
   "$(sudo -n sha256sum "$peer_binary" | cut -d ' ' -f1)" ]] || {
  echo 'E_PEER_PROOF_BINARY_DIGEST_CHANGED' >&2; exit 1;
}
peer_socket_dir="$base/peer-socket"
sudo -n install -d -o jdc-authority -g jdc-authority -m 0711 -- "$peer_socket_dir"
peer_socket="$peer_socket_dir/accepted.sock"
peer_issuer_socket="$peer_socket_dir/issuer.sock"
peer_server_log="$(mktemp -p "${RUNNER_TEMP:?}" jdc-peered-read.XXXXXXXX)"
timeout --kill-after=2s 14s sudo -n -u jdc-authority -- \
  "$peer_binary" serve "$isolated" "$peer_socket" "$peer_issuer_socket" >"$peer_server_log" 2>&1 &
peer_server_pid=$!
peer_ready=0
for ((attempt=0; attempt<80; attempt++)); do
  if [[ -S "$peer_socket" && -S "$peer_issuer_socket" ]]; then peer_ready=1; break; fi
  if ! kill -0 "$peer_server_pid" 2>/dev/null; then break; fi
  sleep 0.025
done
if [[ "$peer_ready" -ne 1 ]]; then
  cat -- "$peer_server_log" >&2
  echo 'E_PEER_PROOF_LISTENER_NOT_READY' >&2
  exit 1
fi
# The exact root-owned launcher must reject invocation by an ordinary
# process, even if that process can execute the same binary and copy args.
if sudo -n -u jdc-mcp-client -- "$peer_binary" issue "$peer_issuer_socket" "$peer_socket"; then
  echo 'E_PEER_PROOF_UNTRUSTED_ISSUER_ACCEPTED' >&2
  exit 1
fi
# The trusted CI administrator issues ONE specific OS client process, retaining
# a real pidfd on the service side. The child performs a genuine confined read
# with exact bytes, not a synthetic self-reported SID/UID/PID.
sudo -n -- "$peer_binary" issue "$peer_issuer_socket" "$peer_socket"
# A different OS principal never receives the protected-root sentinel.
sudo -n -u nobody -- "$peer_binary" deny "$peer_socket"
# The same client UID/GID on a NEW process is no longer sufficient to read.
sudo -n -u jdc-mcp-client -- "$peer_binary" impersonate "$peer_socket"
if ! wait "$peer_server_pid"; then
  cat -- "$peer_server_log" >&2
  echo 'E_PEER_PROOF_SERVER_FAILED' >&2
  exit 1
fi
peer_server_pid=''
grep -Fq 'T011_LINUX_ROOT_ISSUED_PEER_BOUND_READ_PASS_NONRELEASE' "$peer_server_log" || {
  cat -- "$peer_server_log" >&2
  echo 'E_PEER_PROOF_NO_REAL_ISSUER_READ_VERDICT' >&2
  exit 1
}
grep -Fq 'T011_LINUX_SAME_UID_FOREIGN_CLIENT_DENIED' "$peer_server_log" || {
  cat -- "$peer_server_log" >&2
  echo 'E_PEER_PROOF_SAME_UID_DENIAL_NOT_PROVEN' >&2
  exit 1
}
grep -Fq 'T011_LINUX_FOREIGN_UID_DENIED' "$peer_server_log" || {
  cat -- "$peer_server_log" >&2
  echo 'E_PEER_PROOF_FOREIGN_UID_DENIAL_NOT_PROVEN' >&2
  exit 1
}
rm -f -- "$peer_server_log"
peer_server_log=''
[[ "$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)" == \
   "$outside_hash" ]] || { echo 'E_PEER_PROOF_OUTSIDE_CHANGED' >&2; exit 1; }
echo 'T011_LINUX_REAL_SERVICE_PEER_BOUND_READ_PASS_NONRELEASE'
# Official SDK calls the real JDC dispatcher from the root-issued Node
# process whose live PID is attested by the native server. The fixed-object
# adapter is disposable, not a shipping enrollment or general read policy.
sdk_bundle="$(realpath -e -- test/security/support/t011-issued-sdk-native-read.mjs)"
node_binary="$(realpath -e -- "$(command -v node)")"
[[ "$("$node_binary" --version)" == v24.* ]] || exit 1
sudo -n -u jdc-mcp-client -- "$node_binary" --version >/dev/null
sdk_installed="$base/t011-issued-sdk-native-read.mjs"
sudo -n install -o root -g root -m 0555 -- "$sdk_bundle" "$sdk_installed"
[[ "$(sha256sum "$sdk_bundle" | cut -d ' ' -f1)" == \
   "$(sudo -n sha256sum "$sdk_installed" | cut -d ' ' -f1)" ]] || exit 1
[[ "$(sudo -n stat -c '%U:%G:%a' "$sdk_installed")" == 'root:root:555' ]] || exit 1
sudo -n -u jdc-mcp-client -- test -r "$sdk_installed"
# Stage the already built runtime and its locked dependency tree. The issued
# account must not be able to alter either the code or a dependency.
sudo -n cp -a --no-preserve=ownership -- dist node_modules package.json "$base/"
sudo -n chmod -R go-w -- "$base/dist" "$base/node_modules" "$base/package.json"
if [[ -n "$(sudo -n find "$base/dist" "$base/node_modules" "$base/package.json" \
  \( ! -uid 0 -o \( ! -type l -a -perm /022 \) \) -print -quit)" ]]; then
  echo 'E_REAL_JDC_RUNTIME_CUSTODY' >&2; exit 1
fi
while IFS= read -r -d '' link; do
  resolved="$(sudo -n realpath -e -- "$link")"
  [[ "$resolved" == "$base/"* ]] || { echo 'E_REAL_JDC_EXTERNAL_DEPENDENCY' >&2; exit 1; }
done < <(sudo -n find "$base/dist" "$base/node_modules" -type l -print0)
sudo -n install -d -o "$client_uid" -g "$client_gid" -m 0700 -- "$base/client-state"
sudo -n -u jdc-mcp-client -- test -r "$base/dist/server.js"
sdk_socket="$peer_socket_dir/sdk-accepted.sock"
sdk_issuer_socket="$peer_socket_dir/sdk-issuer.sock"
peer_server_log="$(mktemp -p "${RUNNER_TEMP:?}" jdc-sdk-peered.XXXXXXXX)"
timeout --kill-after=2s 14s sudo -n -u jdc-authority -- \
  "$peer_binary" serve "$isolated" "$sdk_socket" "$sdk_issuer_socket" >"$peer_server_log" 2>&1 &
peer_server_pid=$!
peer_ready=0
for ((attempt=0; attempt<80; attempt++)); do
  if [[ -S "$sdk_socket" && -S "$sdk_issuer_socket" ]]; then peer_ready=1; break; fi
  if ! kill -0 "$peer_server_pid" 2>/dev/null; then break; fi
  sleep 0.025
done
if [[ "$peer_ready" -ne 1 ]]; then
  echo 'E_PEER_SDK_LISTENER_NOT_READY' >&2; exit 1
fi
# The issuer has to be root. An untrusted user cannot create the accepted PID.
if sudo -n -u jdc-mcp-client -- "$peer_binary" issue-sdk \
    "$sdk_issuer_socket" "$sdk_socket" "$node_binary" "$sdk_installed"; then
  echo 'E_PEER_SDK_UNTRUSTED_ISSUER_ACCEPTED' >&2; exit 1
fi
if ! sdk_issuer_output="$(sudo -n -- env GITHUB_ACTIONS=true \
  RUNNER_ENVIRONMENT=github-hosted "$peer_binary" issue-sdk \
  "$sdk_issuer_socket" "$sdk_socket" "$node_binary" "$sdk_installed" 2>&1)"; then
  printf '%s\n' "$sdk_issuer_output" >&2; exit 1
fi
grep -Fq 'T011_LINUX_ROOT_ISSUED_OFFICIAL_SDK_NATIVE_BYTES_PASS_NONRELEASE' \
  <<<"$sdk_issuer_output" || { echo 'E_PEER_SDK_TOOL_NOT_PROVEN' >&2; exit 1; }
grep -Fq 'T011_LINUX_ROOT_ISSUED_REAL_JDC_MANAGED_READ_PASS_NONRELEASE' \
  <<<"$sdk_issuer_output" || { echo 'E_REAL_JDC_DISPATCH_NOT_PROVEN' >&2; exit 1; }
sudo -n -u nobody -- "$peer_binary" deny "$sdk_socket"
sudo -n -u jdc-mcp-client -- "$peer_binary" impersonate "$sdk_socket"
if ! wait "$peer_server_pid"; then
  echo 'E_PEER_SDK_SERVER_FAILED' >&2; exit 1
fi
peer_server_pid=''
for marker in T011_LINUX_ROOT_ISSUED_PEER_BOUND_READ_PASS_NONRELEASE \
              T011_LINUX_SAME_UID_FOREIGN_CLIENT_DENIED \
              T011_LINUX_FOREIGN_UID_DENIED; do
  grep -Fq "$marker" "$peer_server_log" || {
    echo "E_PEER_SDK_MISSING_MARKER:$marker" >&2; exit 1;
  }
done
rm -f -- "$peer_server_log"
peer_server_log=''
echo 'T011_LINUX_OFFICIAL_SDK_TO_KERNEL_BOUND_READ_PASS_NONRELEASE'
sudo -n umount -- "$bind_alias"
if findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null; then
  echo 'E_STORAGE_BIND_ALIAS_REMAINS_MOUNTED' >&2; exit 1
fi
[[ "$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)" == "$outside_hash" ]] || exit 1
[[ "$(sudo -n -u jdc-authority -- cat "$service_file")" == SERVICE_DOMAIN_BYTES ]]
echo 'T011_STORAGE_EXTERIOR_BYTES_UNCHANGED'
echo 'T011_STORAGE_LINUX_DOMAIN_PASS_NONRELEASE'
