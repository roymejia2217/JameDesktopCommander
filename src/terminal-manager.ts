import { spawn, spawnSync } from 'child_process';
import { EventEmitter } from 'node:events';
import path from 'path';
import { TerminalSession, CommandExecutionResult, ActiveSession, TimingInfo, OutputEvent } from './types.js';
import { DEFAULT_COMMAND_TIMEOUT } from './config.js';
import { configManager, DEFAULT_MAX_PROCESS_WAIT_MS, normalizeMaxProcessWaitMs } from './config-manager.js';
import {capture} from "./utils/capture.js";
import { analyzeProcessState } from './utils/process-detection.js';

/**
 * Standard Windows PATHEXT value, used to repair a corrupted PATHEXT before
 * spawning child shells.
 *
 * On some Windows Claude Desktop / DXT launches the server process inherits a
 * broken PATHEXT (observed as ".CPL" only). Because we build the child env from
 * { ...process.env }, that broken value would propagate into every spawned
 * shell, stripping ".EXE" and breaking resolution of git / node / python / rg /
 * etc. (and even full-path .exe invocations under PowerShell). See issue #481.
 */
const STANDARD_PATHEXT = '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC';

/**
 * Return a healthy PATHEXT for spawned Windows shells.
 * - Unset           -> use the standard list.
 * - Missing ".EXE"  -> corrupted; merge the standard list with whatever was
 *                      present (preserves any extra extensions, order-stable).
 * - Otherwise       -> leave the inherited value untouched.
 */
function getRepairedPathExt(): string {
  const current = process.env.PATHEXT;
  if (!current) return STANDARD_PATHEXT;
  const exts = current.split(';').map(e => e.trim().toUpperCase()).filter(Boolean);
  if (!exts.includes('.EXE')) {
    return [...new Set([...STANDARD_PATHEXT.split(';'), ...exts])].join(';');
  }
  return current;
}

interface CompletedSession {
  pid: number;
  outputLines: string[];       // Line-based buffer (consistent with active sessions)
  exitCode: number | null;
  startTime: Date;
  endTime: Date;
  bufferedChars: number;       // Joined retained-buffer length at completion
  evictedLines: number;        // Carried over from the active session (see TerminalSession)
  evictedChars: number;
  lastReadIndex: number;       // Preserve offset=0 cursor across active -> completed
  lastReadLineLength: number;  // Preserve partial-line cursor across completion
}

/**
 * Output buffering caps. Without a cap, a process emitting enough output makes
 * string concatenation throw "RangeError: Invalid string length" at V8's max
 * string size (~536M chars) inside a stdout 'data' handler — an uncaught
 * exception that kills the whole server (index.ts exits on uncaughtException).
 * The cap also bounds the join() cost in snapshot reads and event-driven
 * process-state analysis, both of which are O(total output).
 */
export const MAX_BUFFERED_OUTPUT_CHARS = 50 * 1024 * 1024;  // per session; oldest lines evicted first
const MAX_LINE_CHARS = 1024 * 1024;                  // force-split longer lines so eviction can work
const MAX_WAIT_OUTPUT_CHARS = 2 * 1024 * 1024;       // start_process wait buffer (prompt/state detection)
const PROCESS_STATE_TAIL_CHARS = 16 * 1024;          // prompt detection only needs the recent output tail
export const REPL_PROMPT_QUIESCENCE_MS = 100;         // drain independent stdout/stderr pipes before prompt handoff

// Result type for paginated output reading
export interface PaginatedOutputResult {
  lines: string[];
  rawOutput?: string;            // Exact incremental output for offset=0, preserving partial-line appends
  totalLines: number;
  readFrom: number;            // Starting line of this read
  readCount: number;           // Number of lines returned
  remaining: number;           // Lines remaining after this read
  isComplete: boolean;         // Whether process has finished
  exitCode?: number | null;    // Exit code if completed
  runtimeMs?: number;          // Runtime in milliseconds (for completed processes)
  evictedLines?: number;       // Lines dropped by the buffer cap; when > 0, line numbers are relative to the retained buffer
}

/**
 * Configuration for spawning a shell with appropriate flags
 */
interface ShellSpawnConfig {
  executable: string;
  args: string[];
  useShellOption: string | boolean;
  // When true, pass args verbatim on Windows (see executeCommand). Only cmd.exe
  // needs this; its quote parsing conflicts with libuv's default \" escaping.
  windowsVerbatim?: boolean;
}

export interface CommandExecutionControl {
  signal?: AbortSignal;
  onStarted?: (pid: number) => void;
  onOutput?: (source: 'stdout' | 'stderr') => void;
}

export type TerminalSessionChange = 'output' | 'exit' | 'timeout' | 'cancelled';

export function resolveProcessWaitMs(
  requestedTimeoutMs: number,
  configuredWaitMs: unknown,
): number {
  const configured = normalizeMaxProcessWaitMs(configuredWaitMs);

  if (!Number.isFinite(requestedTimeoutMs) || requestedTimeoutMs <= 0) {
    return Math.min(DEFAULT_COMMAND_TIMEOUT, configured);
  }

  return Math.min(requestedTimeoutMs, configured);
}

/**
 * Get the appropriate spawn configuration for a given shell
 * This handles login shell flags for different shell types
 */
function getShellSpawnArgs(shellPath: string, command: string): ShellSpawnConfig {
  const shellName = path.basename(shellPath).toLowerCase();
  
  // Unix shells with login flag support
  if (shellName.includes('bash') || shellName.includes('zsh')) {
    return { 
      executable: shellPath, 
      args: ['-l', '-c', command],
      useShellOption: false 
    };
  }
  
  // PowerShell Core (cross-platform, supports -Login)
  if (shellName === 'pwsh' || shellName === 'pwsh.exe') {
    return { 
      executable: shellPath, 
      args: ['-Login', '-Command', command],
      useShellOption: false 
    };
  }
  
  // Windows PowerShell 5.1 (no login flag support)
  if (shellName === 'powershell' || shellName === 'powershell.exe') {
    return { 
      executable: shellPath, 
      args: ['-Command', command],
      useShellOption: false 
    };
  }
  
  // CMD
  if (shellName === 'cmd' || shellName === 'cmd.exe') {
    return { 
      executable: shellPath, 
      args: ['/c', command],
      windowsVerbatim: true,
      useShellOption: false 
    };
  }
  
  // Fish shell (uses -l for login, -c for command)
  if (shellName.includes('fish')) {
    return { 
      executable: shellPath, 
      args: ['-l', '-c', command],
      useShellOption: false 
    };
  }
  
  // Unknown/other shells - use shell option for safety
  // This provides a fallback for shells we don't explicitly handle
  return { 
    executable: command,
    args: [],
    useShellOption: shellPath 
  };
}

export function terminateProcessTree(pid: number, ownsProcessGroup: boolean = false): boolean {
  if (process.platform === 'win32') {
    const systemRoot = process.env.SystemRoot || process.env.WINDIR;
    const taskkillPath = systemRoot
      ? path.win32.join(systemRoot, 'System32', 'taskkill.exe')
      : 'taskkill.exe';
    const result = spawnSync(taskkillPath, ['/PID', String(pid), '/T', '/F'], {
      windowsHide: true,
      shell: false,
      stdio: 'ignore',
      timeout: 5000,
    });

    if (!result.error && result.status === 0) {
      return true;
    }

    try {
      process.kill(pid, 'SIGKILL');
      return true;
    } catch {
      return false;
    }
  }

  try {
    process.kill(ownsProcessGroup ? -pid : pid, 'SIGKILL');
    return true;
  } catch {
    return false;
  }
}

export class TerminalManager {
  private sessions: Map<number, TerminalSession> = new Map();
  private completedSessions: Map<number, CompletedSession> = new Map();
  private sessionEvents: Map<number, EventEmitter> = new Map();
  
  /**
   * Send input to a running process
   * @param pid Process ID
   * @param input Text to send to the process
   * @returns Whether input was successfully sent
   */
  sendInputToProcess(pid: number, input: string): boolean {
    const session = this.sessions.get(pid);
    if (!session) {
      return false;
    }
    
    try {
      if (session.process.stdin && !session.process.stdin.destroyed) {
        // Ensure input ends with a newline for most REPLs
        const inputWithNewline = input.endsWith('\n') ? input : input + '\n';
        session.process.stdin.write(inputWithNewline);
        return true;
      }
      return false;
    } catch (error) {
      console.error(`Error sending input to process ${pid}:`, error);
      return false;
    }
  }

  private emitSessionChange(pid: number, change: Exclude<TerminalSessionChange, 'timeout' | 'cancelled'>): void {
    this.sessionEvents.get(pid)?.emit('change', change);
  }

  async waitForSessionChange(
    pid: number,
    snapshot: { totalChars: number; lineCount: number },
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<TerminalSessionChange> {
    const currentState = (): TerminalSessionChange | null => {
      if (signal?.aborted) return 'cancelled';
      if (this.hasOutputSinceSnapshot(pid, snapshot)) return 'output';
      // PID values can be reused by the OS. While a current active session
      // exists, it is authoritative over any stale completed-session entry
      // carrying the same numeric PID.
      if (this.sessions.has(pid)) return null;
      return 'exit';
    };

    const immediate = currentState();
    if (immediate) return immediate;

    const emitter = this.sessionEvents.get(pid);
    if (!emitter) return 'exit';

    return new Promise((resolve) => {
      let settled = false;
      let timeout: NodeJS.Timeout | null = null;
      let abortHandler: (() => void) | null = null;

      const cleanup = () => {
        emitter.removeListener('change', onChange);
        if (timeout) clearTimeout(timeout);
        if (abortHandler && signal) signal.removeEventListener('abort', abortHandler);
      };

      const settle = (change: TerminalSessionChange) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(change);
      };

      const onChange = (change: 'output' | 'exit') => settle(change);
      emitter.on('change', onChange);

      const afterSubscribe = currentState();
      if (afterSubscribe) {
        settle(afterSubscribe);
        return;
      }

      timeout = setTimeout(() => settle('timeout'), Math.max(0, timeoutMs));
      if (signal) {
        abortHandler = () => settle('cancelled');
        signal.addEventListener('abort', abortHandler, { once: true });
        if (signal.aborted) abortHandler();
      }
    });
  }

  async waitForSessionExit(
    pid: number,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<Exclude<TerminalSessionChange, 'output'>> {
    const currentState = (): Exclude<TerminalSessionChange, 'output'> | null => {
      if (signal?.aborted) return 'cancelled';
      if (this.sessions.has(pid)) return null;
      return 'exit';
    };

    const immediate = currentState();
    if (immediate) return immediate;

    const emitter = this.sessionEvents.get(pid);
    if (!emitter) return 'exit';

    return new Promise((resolve) => {
      let settled = false;
      let timeout: NodeJS.Timeout | null = null;
      let abortHandler: (() => void) | null = null;

      const cleanup = () => {
        emitter.removeListener('change', onChange);
        if (timeout) clearTimeout(timeout);
        if (abortHandler && signal) signal.removeEventListener('abort', abortHandler);
      };

      const settle = (change: Exclude<TerminalSessionChange, 'output'>) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(change);
      };

      const onChange = (change: 'output' | 'exit') => {
        if (change === 'exit') settle('exit');
      };
      emitter.on('change', onChange);

      const afterSubscribe = currentState();
      if (afterSubscribe) {
        settle(afterSubscribe);
        return;
      }

      timeout = setTimeout(() => settle('timeout'), Math.max(0, timeoutMs));
      if (signal) {
        abortHandler = () => settle('cancelled');
        signal.addEventListener('abort', abortHandler, { once: true });
        if (signal.aborted) abortHandler();
      }
    });
  }
  
  async executeCommand(
    command: string,
    timeoutMs: number = DEFAULT_COMMAND_TIMEOUT,
    shell?: string,
    collectTiming: boolean = false,
    control: CommandExecutionControl = {},
  ): Promise<CommandExecutionResult> {
    let shellToUse: string | boolean | undefined = shell;
    let configuredWaitMs: unknown = DEFAULT_MAX_PROCESS_WAIT_MS;
    try {
      const config = await configManager.getConfig();
      configuredWaitMs = config.maxProcessWaitMs;
      if (!shellToUse) shellToUse = config.defaultShell || true;
    } catch {
      if (!shellToUse) shellToUse = true;
    }
    const effectiveTimeoutMs = resolveProcessWaitMs(timeoutMs, configuredWaitMs);

    // For REPL interactions, we need to ensure stdin, stdout, and stderr are properly configured
    // Note: No special stdio options needed here, Node.js handles pipes by default

    // Enhance SSH commands automatically
    let enhancedCommand = command;
    if (command.trim().startsWith('ssh ') && !command.includes(' -t')) {
      enhancedCommand = command.replace(/^ssh /, 'ssh -t ');
      console.log(`Enhanced SSH command: ${enhancedCommand}`);
    }

    // Get the appropriate spawn configuration for the shell
    let spawnConfig: ShellSpawnConfig;
    let spawnOptions: any;
    
    if (typeof shellToUse === 'string') {
      // Use shell-specific configuration with login flags where appropriate
      spawnConfig = getShellSpawnArgs(shellToUse, enhancedCommand);
      spawnOptions = {
        env: {
          ...process.env,
          TERM: 'xterm-256color'  // Better terminal compatibility
        },
        windowsHide: true  // Prevent visible console windows on Windows
      };

      // Add shell option if needed (for unknown shells)
      if (spawnConfig.useShellOption) {
        spawnOptions.shell = spawnConfig.useShellOption;
      }
    } else {
      // Boolean or undefined shell - use default shell option behavior
      spawnConfig = {
        executable: enhancedCommand,
        args: [],
        useShellOption: shellToUse
      };
      spawnOptions = {
        shell: shellToUse,
        env: {
          ...process.env,
          TERM: 'xterm-256color'
        },
        windowsHide: true  // Prevent visible console windows on Windows
      };
    }

    // Repair PATHEXT on Windows before spawning. On some Windows DXT launches
    // the server process inherits a corrupted PATHEXT (e.g. ".CPL"), which we
    // would otherwise propagate via { ...process.env } and break command
    // resolution (git, node, python, rg, ...) in the spawned shell. See #481.
    if (process.platform === 'win32' && spawnOptions.env) {
      spawnOptions.env.PATHEXT = getRepairedPathExt();
    }

    // On Windows, when we invoke cmd.exe directly and pass the user's command as a
    // single argument, Node/libuv applies MSVCRT-style quoting that escapes embedded
    // double quotes as \" . cmd.exe does not understand that escaping, so any command
    // containing quotes (e.g. a quoted path with spaces like "C:\Program Files\app.exe")
    // is corrupted before the shell ever parses it. Passing arguments verbatim lets
    // cmd handle its own quoting. Scoped to shells that set windowsVerbatim (cmd only)
    // because PowerShell/pwsh have different quote rules and must NOT use verbatim.
    if (process.platform === 'win32' && spawnConfig.windowsVerbatim) {
      spawnOptions.windowsVerbatimArguments = true;
    }

    const ownsProcessGroup = process.platform !== 'win32' && !!control.signal;
    if (ownsProcessGroup) {
      spawnOptions.detached = true;
    }

    if (control.signal?.aborted) {
      return {
        pid: -1,
        output: 'Process start cancelled by caller before launch.',
        isBlocked: false,
        cancelled: true,
      };
    }

    // Spawn the process with appropriate arguments
    const childProcess = spawn(spawnConfig.executable, spawnConfig.args, spawnOptions);
    let output = '';

    // spawn() reports failure asynchronously via an 'error' event; it does not
    // throw. Node rethrows an 'error' that has no listener as an uncaught
    // exception, and our process-level handler (src/index.ts) turns that into
    // process.exit(1). So an unresolvable executable — e.g. shell: "/usr/bin/bash"
    // on Windows — used to kill the entire MCP server one tick AFTER this
    // function had already returned "Failed to get process ID", making the crash
    // look unrelated to the command that caused it. Under `remote` the parent
    // then kept accepting tool calls over a dead stdio pipe ("Not connected").
    //
    // Attach before any return path below, and keep it for the session lifetime
    // so a later runtime error (EPIPE on a closed stdin, ...) can't crash us either.
    let forwardProcessError: ((err: Error) => void) | null = null;
    let pendingProcessError: Error | null = null;
    childProcess.on('error', (err: Error) => {
      if (forwardProcessError) {
        forwardProcessError(err);
      } else {
        pendingProcessError = err;
        console.error(`Process error for "${command}": ${err.message}`);
      }
    });

    // Ensure childProcess.pid is defined before proceeding
    if (!childProcess.pid) {
      // Return a consistent error object instead of throwing
      return {
        pid: -1,  // Use -1 to indicate an error state
        output: 'Error: Failed to get process ID. The command could not be executed.',
        isBlocked: false
      };
    }

    const session: TerminalSession = {
      pid: childProcess.pid,
      process: childProcess,
      outputLines: [],           // Line-based buffer
      lastReadIndex: 0,          // Line cursor for offset=0 incremental reads
      lastReadLineLength: 0,     // Tracks appends to the last consumed unterminated line
      isBlocked: false,
      startTime: new Date(),
      bufferedChars: 0,
      evictedLines: 0,
      evictedChars: 0,
      ownsProcessGroup
    };

    this.sessions.set(childProcess.pid, session);
    this.sessionEvents.set(childProcess.pid, new EventEmitter());
    control.onStarted?.(childProcess.pid);

    // Timing telemetry
    const startTime = Date.now();
    let firstOutputTime: number | undefined;
    let lastOutputTime: number | undefined;
    const outputEvents: OutputEvent[] = [];
    let exitReason: TimingInfo['exitReason'] = 'timeout';

    return new Promise((resolve) => {
      let resolved = false;
      let timeoutHandle: NodeJS.Timeout | null = null;
      let stateAnalysisImmediate: NodeJS.Immediate | null = null;
      let promptQuiescenceHandle: NodeJS.Timeout | null = null;
      let pendingPromptExitReason: 'early_exit_quick_pattern' | 'early_exit_event_state' | null = null;
      let abortHandler: (() => void) | null = null;

      // Quick prompt patterns for immediate detection
      const quickPromptPatterns = />>>\s*$|>\s*$|\$\s*$|#\s*$/;

      const resolveOnce = (result: CommandExecutionResult) => {
        if (resolved) return;
        resolved = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (stateAnalysisImmediate) clearImmediate(stateAnalysisImmediate);
        if (promptQuiescenceHandle) clearTimeout(promptQuiescenceHandle);
        if (abortHandler && control.signal) {
          control.signal.removeEventListener('abort', abortHandler);
        }

        // Add timing info if requested
        if (collectTiming) {
          const endTime = Date.now();
          result.timingInfo = {
            startTime,
            endTime,
            totalDurationMs: endTime - startTime,
            exitReason,
            firstOutputTime,
            lastOutputTime,
            timeToFirstOutputMs: firstOutputTime ? firstOutputTime - startTime : undefined,
            outputEvents: outputEvents.length > 0 ? outputEvents : undefined
          };
        }

        resolve(result);
      };

      // Now that resolveOnce exists, route process errors into it: an error after
      // a successful spawn means the process is gone, so the caller must not sit
      // waiting for output that will never arrive.
      forwardProcessError = (err: Error) => {
        this.emitSessionChange(childProcess.pid!, 'exit');
        this.sessions.delete(childProcess.pid!);
        this.sessionEvents.delete(childProcess.pid!);
        exitReason = 'process_exit';
        resolveOnce({
          pid: childProcess.pid!,
          output: output + `\nProcess error: ${err.message}`,
          isBlocked: false
        });
      };
      // An error emitted between spawn and here (the common case — spawn errors
      // land on the next tick) is replayed rather than dropped.
      if (pendingProcessError) {
        forwardProcessError(pendingProcessError);
      }

      const schedulePromptResolution = (
        reason: 'early_exit_quick_pattern' | 'early_exit_event_state',
      ) => {
        if (resolved) return;
        pendingPromptExitReason = reason;
        if (promptQuiescenceHandle) clearTimeout(promptQuiescenceHandle);
        promptQuiescenceHandle = setTimeout(() => {
          promptQuiescenceHandle = null;
          if (resolved || !pendingPromptExitReason) return;
          session.isBlocked = true;
          exitReason = pendingPromptExitReason;
          resolveOnce({
            pid: childProcess.pid!,
            output,
            isBlocked: true
          });
        }, REPL_PROMPT_QUIESCENCE_MS);
      };

      const analyzeWaitingState = () => {
        if (resolved || !output.trim()) return;
        const recentOutput = output.slice(-PROCESS_STATE_TAIL_CHARS);
        const processState = analyzeProcessState(recentOutput, childProcess.pid);
        if (processState.isWaitingForInput) {
          schedulePromptResolution('early_exit_event_state');
          return;
        }

        // A prompt seen on one pipe remains authoritative while trailing data
        // from the other pipe drains. New output resets the quiet window rather
        // than discarding the already-observed prompt.
        if (pendingPromptExitReason) {
          schedulePromptResolution(pendingPromptExitReason);
        }
      };

      const scheduleStateAnalysis = () => {
        if (resolved || stateAnalysisImmediate) return;
        // Coalesce bursty stdout/stderr notifications into one analysis turn.
        // setImmediate yields to timers/I/O, so the bounded process deadline and
        // cancellation cannot be starved by a high-throughput child process.
        stateAnalysisImmediate = setImmediate(() => {
          stateAnalysisImmediate = null;
          analyzeWaitingState();
        });
      };

      childProcess.stdout.on('data', (data: any) => {
        const text = data.toString();
        const now = Date.now();

        if (promptQuiescenceHandle) {
          clearTimeout(promptQuiescenceHandle);
          promptQuiescenceHandle = null;
        }
        if (!firstOutputTime) firstOutputTime = now;
        lastOutputTime = now;

        // `output` only feeds the wait-phase result and prompt/state detection,
        // so stop growing it once resolved and keep only a bounded tail.
        if (!resolved) {
          output += text;
          if (output.length > MAX_WAIT_OUTPUT_CHARS) {
            output = output.slice(-Math.floor(MAX_WAIT_OUTPUT_CHARS / 2));
          }
        }
        // Append to line-based buffer and wake event-driven waiters.
        this.appendToLineBuffer(session, text);
        this.emitSessionChange(childProcess.pid!, 'output');
        if (!resolved) control.onOutput?.('stdout');

        // Record output event if collecting timing
        if (collectTiming) {
          outputEvents.push({
            timestamp: now,
            deltaMs: now - startTime,
            source: 'stdout',
            length: text.length,
            snippet: text.slice(0, 50).replace(/\n/g, '\\n')
          });
        }

        // A prompt starts a short quiescence window rather than resolving
        // immediately, so trailing output from the other stdio pipe can drain.
        if (quickPromptPatterns.test(text)) {
          if (collectTiming && outputEvents.length > 0) {
            outputEvents[outputEvents.length - 1].matchedPattern = 'quick_pattern';
          }
          schedulePromptResolution('early_exit_quick_pattern');
          return;
        }

        scheduleStateAnalysis();
      });

      childProcess.stderr.on('data', (data: any) => {
        const text = data.toString();
        const now = Date.now();

        if (promptQuiescenceHandle) {
          clearTimeout(promptQuiescenceHandle);
          promptQuiescenceHandle = null;
        }
        if (!firstOutputTime) firstOutputTime = now;
        lastOutputTime = now;

        if (!resolved) {
          output += text;
          if (output.length > MAX_WAIT_OUTPUT_CHARS) {
            output = output.slice(-Math.floor(MAX_WAIT_OUTPUT_CHARS / 2));
          }
        }
        // Append to line-based buffer and wake event-driven waiters.
        this.appendToLineBuffer(session, text);
        this.emitSessionChange(childProcess.pid!, 'output');
        if (!resolved) control.onOutput?.('stderr');

        // Record output event if collecting timing
        if (collectTiming) {
          outputEvents.push({
            timestamp: now,
            deltaMs: now - startTime,
            source: 'stderr',
            length: text.length,
            snippet: text.slice(0, 50).replace(/\n/g, '\\n')
          });
        }

        scheduleStateAnalysis();
      });

      // One-shot deadline: long-running processes remain active, but the MCP
      // call returns before the client-side request ceiling is reached.
      // This is a deadline, not state polling.
      // Timeout fallback
      timeoutHandle = setTimeout(() => {
        session.isBlocked = true;
        exitReason = 'timeout';
        resolveOnce({
          pid: childProcess.pid!,
          output,
          isBlocked: true
        });
      }, effectiveTimeoutMs);

      // Finalize on `close`, not `exit`: Node emits `close` only after the
      // child has ended AND its stdio streams are closed. Finalizing on `exit`
      // can copy the session buffer before trailing stdout/stderr data has been
      // delivered under heavy output, which loses the newest output permanently.
      childProcess.on('close', (code: any) => {
        if (childProcess.pid) {
          this.completedSessions.set(childProcess.pid, {
            pid: childProcess.pid,
            outputLines: [...session.outputLines],
            exitCode: code,
            startTime: session.startTime,
            endTime: new Date(),
            bufferedChars: session.bufferedChars,
            evictedLines: session.evictedLines,
            evictedChars: session.evictedChars,
            lastReadIndex: session.lastReadIndex,
            lastReadLineLength: session.lastReadLineLength
          });

          // Keep only last 100 completed sessions
          if (this.completedSessions.size > 100) {
            const oldestKey = Array.from(this.completedSessions.keys())[0];
            this.completedSessions.delete(oldestKey);
          }

          this.sessions.delete(childProcess.pid);
          this.emitSessionChange(childProcess.pid, 'exit');
          this.sessionEvents.delete(childProcess.pid);
        }
        exitReason = 'process_exit';
        resolveOnce({
          pid: childProcess.pid!,
          output,
          isBlocked: false
        });
      });

      if (control.signal) {
        abortHandler = () => {
          if (resolved || !childProcess.pid) return;
          exitReason = 'cancelled';
          output += (output ? '\n' : '') + 'Process cancelled by caller.';
          terminateProcessTree(childProcess.pid, session.ownsProcessGroup);
          resolveOnce({
            pid: childProcess.pid,
            output,
            isBlocked: false,
            cancelled: true,
          });
        };
        control.signal.addEventListener('abort', abortHandler, { once: true });
        if (control.signal.aborted) {
          abortHandler();
        }
      }
    });
  }

  /**
   * Append text to a session's line buffer
   * Handles partial lines and newline splitting
   */
  private appendToLineBuffer(session: TerminalSession, text: string): void {
    if (!text) return;

    // Split text into lines, keeping track of whether text ends with newline
    const lines = text.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const isLastFragment = i === lines.length - 1;
      const endsWithNewline = text.endsWith('\n');

      if (session.outputLines.length === 0) {
        // First line ever
        session.outputLines.push(line);
      } else if (i === 0) {
        // First fragment - append to last line (might be partial)
        session.outputLines[session.outputLines.length - 1] += line;
      } else {
        // Subsequent lines - add as new lines
        session.outputLines.push(line);
      }
    }
    // Appended text contributes exactly its length to the joined buffer
    // (its newlines become the join separators).
    session.bufferedChars += text.length;

    // A process printing without newlines grows a single line forever, which
    // eviction can't bound — force-split so no line exceeds MAX_LINE_CHARS.
    // Each inserted break adds one separator to the joined length.
    let lastIndex = session.outputLines.length - 1;
    while (session.outputLines[lastIndex].length > MAX_LINE_CHARS) {
      const overlong = session.outputLines[lastIndex];
      session.outputLines[lastIndex] = overlong.slice(0, MAX_LINE_CHARS);
      session.outputLines.push(overlong.slice(MAX_LINE_CHARS));
      session.bufferedChars += 1;
      lastIndex++;
    }

    // Enforce the per-session cap by evicting the oldest lines. Keeps the
    // buffer far below V8's max string length so concatenation and join()
    // can never throw "Invalid string length" and kill the server.
    while (session.bufferedChars > MAX_BUFFERED_OUTPUT_CHARS && session.outputLines.length > 1) {
      const dropped = session.outputLines.shift()!;
      const droppedJoinedChars = dropped.length + 1; // +1 for its join separator
      session.bufferedChars -= droppedJoinedChars;
      session.evictedChars += droppedJoinedChars;
      session.evictedLines++;
      if (session.lastReadIndex > 0) {
        session.lastReadIndex--;
        if (session.lastReadIndex === 0) session.lastReadLineLength = 0;
      }
    }
  }

  /**
   * Read process output with pagination (like file reading)
   * @param pid Process ID
   * @param offset Line offset: 0=from lastReadIndex, positive=absolute, negative=tail
   * @param length Max lines to return
   * @param updateReadIndex Whether to update lastReadIndex (default: true for offset=0)
   */
  readOutputPaginated(pid: number, offset: number = 0, length: number = 1000): PaginatedOutputResult | null {
    // First check active sessions.
    const session = this.sessions.get(pid);
    if (session) {
      const result = offset === 0
        ? this.readIncrementalOutput(session, length)
        : this.readFromLineBuffer(
            session.outputLines,
            offset,
            length,
            session.lastReadIndex,
            () => {},
            false,
            undefined,
          );
      result.evictedLines = session.evictedLines;
      return result;
    }

    // Then check completed sessions.
    const completedSession = this.completedSessions.get(pid);
    if (completedSession) {
      const runtimeMs = completedSession.endTime.getTime() - completedSession.startTime.getTime();
      const result = offset === 0
        ? this.readIncrementalOutput(completedSession, length)
        : this.readFromLineBuffer(
            completedSession.outputLines,
            offset,
            length,
            completedSession.lastReadIndex,
            () => {},
            true,
            completedSession.exitCode,
            runtimeMs,
          );

      result.isComplete = true;
      result.exitCode = completedSession.exitCode;
      result.runtimeMs = runtimeMs;
      result.evictedLines = completedSession.evictedLines;
      return result;
    }

    return null;
  }

  private readIncrementalOutput(
    session: TerminalSession | CompletedSession,
    length: number,
  ): PaginatedOutputResult {
    const totalLines = session.outputLines.length;
    const startIndex = Math.min(session.lastReadIndex, totalLines);
    let appendedFragment = '';

    if (startIndex > 0) {
      const lastConsumedLine = session.outputLines[startIndex - 1] ?? '';
      if (lastConsumedLine.length > session.lastReadLineLength) {
        appendedFragment = lastConsumedLine.slice(session.lastReadLineLength);
      }
    }

    const fragmentBudget = appendedFragment ? 1 : 0;
    const lineBudget = Math.max(0, length - fragmentBudget);
    const newLines = lineBudget > 0
      ? session.outputLines.slice(startIndex, startIndex + lineBudget)
      : [];
    const lines = appendedFragment ? [appendedFragment, ...newLines] : newLines;
    const nextIndex = startIndex + newLines.length;

    session.lastReadIndex = nextIndex;
    if (newLines.length > 0) {
      session.lastReadLineLength = session.outputLines[nextIndex - 1]?.length ?? 0;
    } else if (appendedFragment && startIndex > 0) {
      session.lastReadLineLength = session.outputLines[startIndex - 1]?.length ?? 0;
    } else if (nextIndex === 0) {
      session.lastReadLineLength = 0;
    }

    return {
      lines,
      rawOutput: lines.join('\n'),
      totalLines,
      readFrom: appendedFragment ? Math.max(0, startIndex - 1) : startIndex,
      readCount: lines.length,
      remaining: Math.max(0, totalLines - nextIndex),
      isComplete: false,
    };
  }

  /**
   * Internal helper to read from a line buffer with offset/length
   */
  private readFromLineBuffer(
    lines: string[],
    offset: number,
    length: number,
    lastReadIndex: number,
    updateLastRead: (index: number) => void,
    isComplete: boolean,
    exitCode?: number | null,
    runtimeMs?: number
  ): PaginatedOutputResult {
    const totalLines = lines.length;
    let startIndex: number;
    let linesToRead: string[];

    if (offset < 0) {
      // Negative offset = start position from end, then read 'length' lines forward
      // e.g., offset=-50, length=10 means: start 50 lines from end, read 10 lines
      const fromEnd = Math.abs(offset);
      startIndex = Math.max(0, totalLines - fromEnd);
      linesToRead = lines.slice(startIndex, startIndex + length);
      // Don't update lastReadIndex for tail reads
    } else if (offset === 0) {
      // offset=0 means "from where I last read" (like getNewOutput)
      startIndex = lastReadIndex;
      linesToRead = lines.slice(startIndex, startIndex + length);
      // Update lastReadIndex for "new output" behavior
      updateLastRead(Math.min(startIndex + linesToRead.length, totalLines));
    } else {
      // Positive offset = absolute position
      startIndex = offset;
      linesToRead = lines.slice(startIndex, startIndex + length);
      // Don't update lastReadIndex for absolute position reads
    }

    const readCount = linesToRead.length;
    const endIndex = startIndex + readCount;
    const remaining = Math.max(0, totalLines - endIndex);

    return {
      lines: linesToRead,
      totalLines,
      readFrom: startIndex,
      readCount,
      remaining,
      isComplete,
      exitCode,
      runtimeMs
    };
  }

  hasUnreadOutput(pid: number): boolean {
    const session = this.sessions.get(pid);
    if (!session) return false;

    if (session.outputLines.length > session.lastReadIndex) {
      return true;
    }

    if (session.lastReadIndex > 0) {
      const lastConsumedLine = session.outputLines[session.lastReadIndex - 1] ?? '';
      return lastConsumedLine.length > session.lastReadLineLength;
    }

    return false;
  }

  /**
   * Get total line count for a process
   */
  getOutputLineCount(pid: number): number | null {
    const session = this.sessions.get(pid);
    if (session) {
      return session.outputLines.length;
    }

    const completedSession = this.completedSessions.get(pid);
    if (completedSession) {
      return completedSession.outputLines.length;
    }

    return null;
  }

  /**
   * Legacy method for backward compatibility
   * Returns all new output since last read
   * @param maxLines Maximum lines to return (default: 1000 for context protection)
   * @deprecated Use readOutputPaginated instead
   */
  getNewOutput(pid: number, maxLines: number = 1000): string | null {
    const result = this.readOutputPaginated(pid, 0, maxLines);
    if (!result) return null;

    const output = result.lines.join('\n').trim();

    // For completed sessions, append completion info with runtime
    if (result.isComplete) {
      const runtimeStr = result.runtimeMs !== undefined 
        ? `\nRuntime: ${(result.runtimeMs / 1000).toFixed(2)}s` 
        : '';
      if (output) {
        return `${output}\n\nProcess completed with exit code ${result.exitCode}${runtimeStr}`;
      } else {
        return `Process completed with exit code ${result.exitCode}${runtimeStr}\n(No output produced)`;
      }
    }

    // Add truncation warning if there's more output
    if (result.remaining > 0) {
      return `${output}\n\n[Output truncated: ${result.remaining} more lines available. Use read_process_output with offset/length for full output.]`;
    }

    return output || null;
  }

  /**
   * Capture a snapshot of current output state for interaction tracking.
   * Uses maintained counters, so snapshotting is O(1) regardless of retained
   * output size.
   */
  captureOutputSnapshot(pid: number): { totalChars: number; lineCount: number } | null {
    const session = this.sessions.get(pid);
    if (session) {
      return {
        // Absolute since process start (includes evicted output), so the
        // offset stays valid even if the cap evicts lines between reads.
        totalChars: session.evictedChars + session.bufferedChars,
        lineCount: session.evictedLines + session.outputLines.length
      };
    }

    const completedSession = this.completedSessions.get(pid);
    if (completedSession) {
      return {
        totalChars: completedSession.evictedChars + completedSession.bufferedChars,
        lineCount: completedSession.evictedLines + completedSession.outputLines.length
      };
    }

    return null;
  }

  hasOutputSinceSnapshot(
    pid: number,
    snapshot: { totalChars: number; lineCount: number },
  ): boolean {
    const session = this.sessions.get(pid);
    if (session) {
      return session.evictedChars + session.bufferedChars > snapshot.totalChars;
    }

    const completedSession = this.completedSessions.get(pid);
    if (completedSession) {
      return completedSession.evictedChars + completedSession.bufferedChars > snapshot.totalChars;
    }

    return false;
  }

  getOutputTail(pid: number, maxChars: number = PROCESS_STATE_TAIL_CHARS): string {
    if (!Number.isFinite(maxChars) || maxChars <= 0) return '';
    const session = this.sessions.get(pid);
    if (session) {
      return TerminalManager.tailFromLineBuffer(session.outputLines, Math.floor(maxChars));
    }

    const completedSession = this.completedSessions.get(pid);
    if (completedSession) {
      return TerminalManager.tailFromLineBuffer(completedSession.outputLines, Math.floor(maxChars));
    }

    return '';
  }

  /**
   * Get output that appeared since a snapshot was taken.
   * This handles appends to partial lines and avoids joining the full retained
   * buffer; only the unseen tail is materialized.
   */
  getOutputSinceSnapshot(pid: number, snapshot: { totalChars: number; lineCount: number }): string | null {
    return this.getOutputSinceSnapshotLimited(pid, snapshot, Number.POSITIVE_INFINITY);
  }

  getOutputTailSinceSnapshot(
    pid: number,
    snapshot: { totalChars: number; lineCount: number },
    maxChars: number = PROCESS_STATE_TAIL_CHARS,
  ): string | null {
    return this.getOutputSinceSnapshotLimited(pid, snapshot, maxChars);
  }

  private getOutputSinceSnapshotLimited(
    pid: number,
    snapshot: { totalChars: number; lineCount: number },
    maxChars: number,
  ): string | null {
    const session = this.sessions.get(pid);
    if (session) {
      return TerminalManager.outputSinceSnapshot(
        session.outputLines,
        session.evictedChars,
        session.bufferedChars,
        snapshot.totalChars,
        maxChars,
      );
    }

    const completedSession = this.completedSessions.get(pid);
    if (completedSession) {
      return TerminalManager.outputSinceSnapshot(
        completedSession.outputLines,
        completedSession.evictedChars,
        completedSession.bufferedChars,
        snapshot.totalChars,
        maxChars,
      );
    }

    return null;
  }

  private static outputSinceSnapshot(
    outputLines: string[],
    evictedChars: number,
    bufferedChars: number,
    snapshotTotalChars: number,
    maxChars: number,
  ): string {
    const newChars = evictedChars + bufferedChars - snapshotTotalChars;
    if (newChars <= 0) return '';
    const boundedMaxChars = Number.isFinite(maxChars)
      ? Math.max(0, Math.floor(maxChars))
      : bufferedChars;
    return TerminalManager.tailFromLineBuffer(
      outputLines,
      Math.min(newChars, bufferedChars, boundedMaxChars),
    );
  }

  private static tailFromLineBuffer(outputLines: string[], maxChars: number): string {
    if (maxChars <= 0 || outputLines.length === 0) return '';

    let remaining = maxChars;
    const reverseChunks: string[] = [];
    for (let index = outputLines.length - 1; index >= 0 && remaining > 0; index--) {
      const line = outputLines[index];
      const take = Math.min(line.length, remaining);
      if (take > 0) {
        reverseChunks.push(line.slice(line.length - take));
        remaining -= take;
      }

      if (index > 0 && remaining > 0) {
        reverseChunks.push('\n');
        remaining -= 1;
      }

      if (take < line.length) break;
    }

    return reverseChunks.reverse().join('');
  }

    /**
   * Get a session by PID
   * @param pid Process ID
   * @returns The session or undefined if not found
   */
  getSession(pid: number): TerminalSession | undefined {
    return this.sessions.get(pid);
  }

  forceTerminate(pid: number): boolean {
    const session = this.sessions.get(pid);
    if (!session) {
      return false;
    }

    const terminated = terminateProcessTree(pid, session.ownsProcessGroup);
    if (!terminated) {
      capture('server_request_error', {
        error: 'process tree termination failed',
        message: `Failed to terminate process ${pid}:`,
      });
    }
    return terminated;
  }

  listActiveSessions(): ActiveSession[] {
    const now = new Date();
    return Array.from(this.sessions.values()).map(session => ({
      pid: session.pid,
      isBlocked: session.isBlocked,
      runtime: now.getTime() - session.startTime.getTime()
    }));
  }

  listCompletedSessions(): CompletedSession[] {
    return Array.from(this.completedSessions.values());
  }
}

export const terminalManager = new TerminalManager();