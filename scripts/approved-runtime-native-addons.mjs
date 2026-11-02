// Only existing lockfile-managed runtime dependencies may ship N-API binaries.
// An approved package is not an approval of JDC's experimental capability addon.
const approvedPackages = Object.freeze({
  'win32-x64': new Set([
    '@img/sharp-win32-x64',
    '@koromix/koffi-win32-x64',
    '@napi-rs/keyring-win32-x64-msvc',
    '@rolldown/binding-win32-x64-msvc',
    '@rollup/rollup-win32-x64-msvc',
    'lightningcss-win32-x64-msvc',
  ]),
  'linux-x64': new Set([
    '@img/sharp-linux-x64',
    '@koromix/koffi-linux-x64',
    '@napi-rs/keyring-linux-x64-gnu',
    '@rolldown/binding-linux-x64-gnu',
    '@rollup/rollup-linux-x64-gnu',
    'lightningcss-linux-x64-gnu',
  ]),
});

export function approvedRuntimeNativeAddon(path, target) {
  if (typeof path !== 'string' || !path.startsWith('node_modules/') ||
      !path.toLowerCase().endsWith('.node')) return false;
  const segments = path.slice('node_modules/'.length).split('/');
  const scoped = segments[0]?.startsWith('@');
  const count = scoped ? 2 : 1;
  const pkg = segments.slice(0, count).join('/');
  return segments.length > count &&
    segments.every(segment => segment && segment !== '.' && segment !== '..') &&
    (approvedPackages[target]?.has(pkg) ?? false);
}
