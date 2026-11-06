# JDC Native Local Tunnel Operator (development acceptance)

This is the **native Windows read-only UI milestone**, not an installable
release or an authorization primitive. The parent task is #270, with final
acceptance owned by #248; #124/#139/#148 and Linux #150 remain open gates.

## Toolchain and build

Use **Rust 1.95** and the checked-in `Cargo.lock` with `eframe =0.37.0`.
Do not silently reuse an older 1.91 native T011 toolchain for this crate.

```text
cargo +1.95.0 test --locked --all-targets
cargo +1.95.0 clippy --locked --all-targets -- -D warnings
cargo +1.95.0 fmt --all -- --check
cargo +1.95.0 build --locked
```

## Read-only runtime contract

The UI executable must be installed at a **fixed package root** next to
`runtime/node.exe` on Windows (on Linux: `runtime/node`) and `dist/index.js`.
It invokes the installed backend with literal `tunnel overview` arguments,
`shell=false`, closed stdin, fixed bounded process timeout and stdout,
no NODE_OPTIONS/NODE_PATH injection and no stderr/provider text disclosure.
All displayed fields are validated against `tunnel_operator_overview_v1`.
There is no automatic status polling. The operator clicks **Refresh
observation**; the UI shows the backend observation timestamp and a separate
local receive age. A missing, invalid, stale or conflicting observation must
remain UNKNOWN, not become Healthy. MCP initialization, tool discovery,
control-plane status, and genuine remote ChatGPT delivery are distinct.

**Unavailable controls:** no Start, Stop, Restart, Rotate, credential entry,
profile editing or alternate backend executable chooser. Enabling any of these
requires independent interactive-operator authentication and native Windows/
Linux installed task/profile/file custody, durable generation fencing, crash
recovery, remote authentication and complete adversarial tests.

## Acceptance remaining before a distributable user UI

- Bind GUI executable to verified install provenance and integrated package
  candidate manifest (not just relative filenames). Unit tests and a manually
  staged development binary are not evidence of a signed installer.
- Prove real GUI startup, keyboard navigation/focus, offline/unavailable state,
  visual legibility and screen reader semantics in a Windows interactive
  session. A running process alone is not proof of usable UX.
- Add Windows/Linux exact Rust 1.95 source-build CI, test-only real packaged
  backend probes and .exe/.deb installation/uninstallation checks.
- Implement separate Linux `overview` projection on native user-systemd;
  this first Windows adapter must not be advertised as Linux complete.
- Only after security review, build and test independently authorized
  lifecycle and transactional one-shot credential recovery backend, then
  enable the matching GUI controls.

Existing Windows installed runtime remains immutable. Never copy a test UI
binary into the protected installed runtime or rotate live credentials during
CI. Report exact SHA and the remaining NO-GO gates.

## 2026-11-06 interactive Windows acceptance evidence

The first Glow executable failed in the noninteractive service context with
`egui_glow requires opengl 2.0+`. This alone was not evidence of a GPU defect.
In the actual logged-on Roy console session (session 2), the initial default
WGPU/Vulkan build **crashed with 0xC0000005** in the Intel Vulkan driver
`igvk64.dll` version `30.0.100.9805` (Windows Application Error event 1000).
The ephemeral **development-only** Task Scheduler registration was removed
and no trial UI process remained. No installed tunnel task was touched.

The implementation now configures the official wgpu instance backends
explicitly: **Direct3D 12 only on Windows** (avoiding the crashing Vulkan ICD)
and Vulkan or GL on Linux. This choice is verified by a Rust unit test;
compilation and unit tests are **not** visual acceptance. The Windows GUI
uses the Windows subsystem to avoid an unwanted companion console window,
so the native UI can become the foreground interactive window.

The isolated Windows worktree staging copied the built UI and Node executable
under the worktree solely for tests; it is not installed or production signed.
A prior PowerShell stage-preexistence check was malformed and did not run as
designed; subsequent tests explicitly guarded and checked development paths.
Do not interpret the absence of production modification as proof that the
visual journey has been accepted. Acceptance requires an actual window and
UI Automation evidence, with test process/task cleanup and no driver changes.

### Interactive DX12 validation — PASS for initial display only

After explicitly selecting Direct3D 12 and using the Windows GUI subsystem,
the development binary started in the real interactive console session 2.
Windows UI Automation confirmed a foreground window titled
`JameDesktopCommander — Local Tunnel Operator` and the actual app controls:
Overview, Diagnose, enabled Refresh observation, and **disabled** Credentials
and Lifecycle. The application rendered the backend's real
`UNVERIFIED / MCP_TOOLS_LIST_UNVERIFIED` verdict and distinct local/MCP/
remote evidence, including a stale-sample warning after 30 seconds.
The native GUI test task and its one-shot foreground helper were both
unregistered, and the development process was terminated without touching
the installed production tunnel. This is **not** proof of complete keyboard
navigation, screen reader interaction, safe credential rotation, remote MCP
round trip, installable packaging or Linux parity. Those remain release gates.
