// Exact native payload paths observed in pinned, target-specific npm packages.
// Package-name-only admission would also permit a second injected .node file.
const approvedPaths = Object.freeze({
  'win32-x64': new Set([
    'node_modules/@img/sharp-win32-x64/lib/sharp-win32-x64-0.35.5.node',
    'node_modules/@koromix/koffi-win32-x64/win32_x64/koffi.node',
    'node_modules/@napi-rs/keyring-win32-x64-msvc/keyring.win32-x64-msvc.node',
    'node_modules/@rolldown/binding-win32-x64-msvc/rolldown-binding.win32-x64-msvc.node',
    'node_modules/@rollup/rollup-win32-x64-msvc/rollup.win32-x64-msvc.node',
    'node_modules/lightningcss-win32-x64-msvc/lightningcss.win32-x64-msvc.node',
  ]),
  'linux-x64': new Set([
    'node_modules/@img/sharp-linux-x64/lib/sharp-linux-x64-0.35.5.node',
    'node_modules/@koromix/koffi-linux-x64/linux_x64/koffi.node',
    'node_modules/@koromix/koffi-linux-x64/musl_x64/koffi.node',
    'node_modules/@napi-rs/keyring-linux-x64-gnu/keyring.linux-x64-gnu.node',
    'node_modules/@rolldown/binding-linux-x64-gnu/rolldown-binding.linux-x64-gnu.node',
    'node_modules/@rollup/rollup-linux-x64-gnu/rollup.linux-x64-gnu.node',
    'node_modules/lightningcss-linux-x64-gnu/lightningcss.linux-x64-gnu.node',
  ]),
});

export function approvedRuntimeNativeAddon(path, target) {
  return typeof path === 'string' &&
    (approvedPaths[target]?.has(path) ?? false);
}
