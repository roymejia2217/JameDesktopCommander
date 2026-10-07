import { terminalManager, MAX_BUFFERED_OUTPUT_CHARS, REPL_PROMPT_QUIESCENCE_MS, resolveProcessWaitMs } from '../terminal-manager.js';
import { commandManager } from '../command-manager.js';
import { StartProcessArgsSchema, ReadProcessOutputArgsSchema, InteractWithProcessArgsSchema, ForceTerminateArgsSchema, ListSessionsArgsSchema } from './schemas.js';
import { capture } from "../utils/capture.js";
import { ServerResult, type ToolExecutionContext } from '../types.js';
import { analyzeProcessState, cleanProcessOutput, formatProcessStateMessage, ProcessState } from '../utils/process-detection.js';
import * as os from 'os';
import { configManager } from '../config-manager.js';
import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// Get the directory where the MCP is installed (for ES module imports)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const mcpRoot = path.resolve(__dirname, '..', '..');

// Track virtual Node sessions (PIDs that are actually Node fallback sessions)
const virtualNodeSessions = new Map<number, { timeout_ms: number }>();
let virtualPidCounter = -1000; // Use negative PIDs for virtual sessions

/**
 * Execute Node.js code via temp file (fallback when Python unavailable)
 * Creates temp .mjs file in MCP directory for ES module import access
 */
async function executeNodeCode(code: string, timeout_ms: number = 30000): Promise<ServerResult> {
  const tempFile = path.join(mcpRoot, `.mcp-exec-${Date.now()}-${Math.random().toString(36).slice(2)}.mjs`);

  try {
    await fs.writeFile(tempFile, code, 'utf8');

    const result = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve) => {
      const proc = spawn(process.execPath, [tempFile], {
        cwd: mcpRoot,
        timeout: timeout_ms,
        windowsHide: true  // Prevent visible console windows on Windows
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (exitCode) => {
        resolve({ stdout, stderr, exitCode: exitCode ?? 1 });
      });

      proc.on('error', (err) => {
        resolve({ stdout, stderr: stderr + '\n' + err.message, exitCode: 1 });
      });
    });

    // Clean up temp file
    await fs.unlink(tempFile).catch(() => {});

    if (result.exitCode !== 0) {
      return {
        content: [{
          type: "text",
          text: `Execution failed (exit code ${result.exitCode}):\n${result.stderr}\n${result.stdout}`
        }],
        isError: true
      };
    }

    return {
      content: [{
        type: "text",
        text: result.stdout || '(no output)'
      }]
    };

  } catch (error) {
    // Clean up temp file on error
    await fs.unlink(tempFile).catch(() => {});

    return {
      content: [{
        type: "text",
        text: `Failed to execute Node.js code: ${error instanceof Error ? error.message : String(error)}`
      }],
      isError: true
    };
  }
}

/**
 * Start a new process (renamed from execute_command)
 * Includes early detection of process waiting for input
 */
export async function startProcess(
  args: unknown,
  context?: ToolExecutionContext,
): Promise<ServerResult> {
  const parsed = StartProcessArgsSchema.safeParse(args);
  if (!parsed.success) {
    capture('server_start_process_failed');
    return {
      content: [{ type: "text", text: `Error: Invalid arguments for start_process: ${parsed.error}` }],
      isError: true,
    };
  }

  if (context?.signal?.aborted) {
    return {
      content: [{ type: "text", text: 'Process start cancelled by caller.' }],
      isError: true,
    };
  }

  let progressValue = 0;
  let progressQueue: Promise<void> = Promise.resolve();
  const queueProgress = (message: string) => {
    const reporter = context?.reportProgress;
    if (!reporter) return;
    const progress = ++progressValue;
    progressQueue = progressQueue
      .then(() => reporter({ progress, message }))
      .catch(() => {
        capture('server_progress_notification_failed', { tool_name: 'start_process' });
      });
  };

  try {
    const commands = commandManager.extractCommands(parsed.data.command).join(', ');
    capture('server_start_process', {
      command: commandManager.getBaseCommand(parsed.data.command),
      commands: commands
    });
  } catch (error) {
    capture('server_start_process', {
      command: commandManager.getBaseCommand(parsed.data.command)
    });
  }

  const isAllowed = await commandManager.validateCommand(parsed.data.command);
  if (!isAllowed) {
    return {
      content: [{ type: "text", text: `Error: Command not allowed: ${parsed.data.command}` }],
      isError: true,
    };
  }

  const commandToRun = parsed.data.command;
  queueProgress('Starting process');

  // Handle node:local - runs Node.js code directly on MCP server
  if (commandToRun.trim() === 'node:local') {
    const virtualPid = virtualPidCounter--;
    virtualNodeSessions.set(virtualPid, { timeout_ms: parsed.data.timeout_ms || 30000 });
    queueProgress(`Process started (PID ${virtualPid})`);
    await progressQueue;

    return {
      content: [{
        type: "text",
        text: `Node.js session started with PID ${virtualPid} (MCP server execution)

   IMPORTANT: Each interact_with_process call runs as a FRESH script.
   State is NOT preserved between calls. Include ALL code in ONE call:
   - imports, file reading, processing, and output together.

   Available libraries:
   - ExcelJS for Excel files: import ExcelJS from 'exceljs'
   - All Node.js built-ins: fs, path, http, crypto, etc.

🔄 Ready for code - send complete self-contained script via interact_with_process.`
      }],
    };
  }

  let shellUsed: string | undefined = parsed.data.shell;

  if (!shellUsed) {
    const config = await configManager.getConfig();
    if (config.defaultShell) {
      shellUsed = config.defaultShell;
    } else {
      const isWindows = os.platform() === 'win32';
      if (isWindows && process.env.COMSPEC) {
        shellUsed = process.env.COMSPEC;
      } else if (!isWindows && process.env.SHELL) {
        shellUsed = process.env.SHELL;
      } else {
        shellUsed = isWindows ? 'cmd.exe' : '/bin/sh';
      }
    }
  }

  let outputReported = false;
  const result = await terminalManager.executeCommand(
    commandToRun,
    parsed.data.timeout_ms,
    shellUsed,
    parsed.data.verbose_timing || false,
    {
      signal: context?.signal,
      onStarted: (pid) => queueProgress(`Process started (PID ${pid})`),
      onOutput: (source) => {
        if (outputReported) return;
        outputReported = true;
        queueProgress(`Process produced ${source} output`);
      },
    },
  );
  await progressQueue;

  if (result.cancelled) {
    return {
      content: [{ type: "text", text: result.output || 'Process cancelled by caller.' }],
      isError: true,
    };
  }

  if (result.pid === -1) {
    return {
      content: [{ type: "text", text: result.output }],
      isError: true,
    };
  }

  // Analyze the process state to detect if it's waiting for input
  const processState = analyzeProcessState(result.output, result.pid);

  let statusMessage = '';
  if (processState.isWaitingForInput) {
    statusMessage = `\n🔄 ${formatProcessStateMessage(processState, result.pid)}`;
  } else if (processState.isFinished) {
    statusMessage = `\n✅ ${formatProcessStateMessage(processState, result.pid)}`;
  } else if (result.isBlocked) {
    statusMessage = '\n⏳ Process is running. Use read_process_output to get more output.';
  }

  // Add timing information if requested
  let timingMessage = '';
  if (result.timingInfo) {
    timingMessage = formatTimingInfo(result.timingInfo);
  }

  return {
    content: [{
      type: "text",
      text: `Process started with PID ${result.pid} (shell: ${shellUsed})\nInitial output:\n${result.output}${statusMessage}${timingMessage}`
    }],
  };
}

function formatTimingInfo(timing: any): string {
  let msg = '\n\n📊 Timing Information:\n';
  msg += `  Exit Reason: ${timing.exitReason}\n`;
  msg += `  Total Duration: ${timing.totalDurationMs}ms\n`;

  if (timing.timeToFirstOutputMs !== undefined) {
    msg += `  Time to First Output: ${timing.timeToFirstOutputMs}ms\n`;
  }

  if (timing.firstOutputTime && timing.lastOutputTime) {
    msg += `  Output Window: ${timing.lastOutputTime - timing.firstOutputTime}ms\n`;
  }

  if (timing.outputEvents && timing.outputEvents.length > 0) {
    msg += `\n  Output Events (${timing.outputEvents.length} total):\n`;
    timing.outputEvents.forEach((event: any, idx: number) => {
      msg += `    [${idx + 1}] +${event.deltaMs}ms | ${event.source} | ${event.length}b`;
      if (event.matchedPattern) {
        msg += ` | 🎯 ${event.matchedPattern}`;
      }
      msg += `\n       "${event.snippet}"\n`;
    });
  }

  return msg;
}

/**
 * Read output from a running process with file-like pagination
 * Supports offset/length parameters for controlled reading
 */
export async function readProcessOutput(
  args: unknown,
  context?: ToolExecutionContext,
): Promise<ServerResult> {
  const parsed = ReadProcessOutputArgsSchema.safeParse(args);
  if (!parsed.success) {
    return {
      content: [{ type: "text", text: `Error: Invalid arguments for read_process_output: ${parsed.error}` }],
      isError: true,
    };
  }

  // Get default line limit from config
  const config = await configManager.getConfig();
  const defaultLength = config.fileReadLineLimit ?? 1000;

  const { 
    pid, 
    timeout_ms = 5000, 
    offset = 0,                    // 0 = from last read, positive = absolute, negative = tail
    length = defaultLength,        // Default from config, same as file reading
    verbose_timing = false 
  } = parsed.data;
  const effectiveWaitMs = resolveProcessWaitMs(timeout_ms, config.maxProcessWaitMs);

  // Timing telemetry
  const startTime = Date.now();

  if (context?.signal?.aborted) {
    return {
      content: [{ type: "text", text: `Reading process ${pid} output was cancelled by caller.` }],
      isError: true,
    };
  }

  let progressValue = 0;
  let progressQueue: Promise<void> = Promise.resolve();
  const queueProgress = (message: string) => {
    const reporter = context?.reportProgress;
    if (!reporter) return;
    const progress = ++progressValue;
    progressQueue = progressQueue
      .then(() => reporter({ progress, message }))
      .catch(() => {
        capture('server_progress_notification_failed', { tool_name: 'read_process_output' });
      });
  };

  // For active sessions with no unread output yet, wait on native process
  // output/exit signals. A single deadline bounds the tool call; there is no
  // fixed-interval state polling.
  const session = terminalManager.getSession(pid);
  if (session && offset === 0) {
    if (!terminalManager.hasUnreadOutput(pid)) {
      const snapshot = terminalManager.captureOutputSnapshot(pid);
      if (snapshot) {
        queueProgress(`Waiting for output from process ${pid}`);
        const waitResult = await terminalManager.waitForSessionChange(
          pid,
          snapshot,
          effectiveWaitMs,
          context?.signal,
        );
        await progressQueue;

        if (waitResult === 'cancelled') {
          return {
            content: [{ type: "text", text: `Reading process ${pid} output was cancelled by caller.` }],
            isError: true,
          };
        }

        if (waitResult === 'output' || waitResult === 'exit') {
          queueProgress(
            waitResult === 'output'
              ? `Output is available from process ${pid}`
              : `Process ${pid} completed`,
          );
          await progressQueue;
        }
      }
    }
  }

  // Read output with pagination
  const result = terminalManager.readOutputPaginated(pid, offset, length);
  
  if (!result) {
    return {
      content: [{ type: "text", text: `No session found for PID ${pid}` }],
      isError: true,
    };
  }

  // Preserve exact incremental output when an already-read partial line grew;
  // otherwise fall back to the normal line-based representation.
  const output = result.rawOutput ?? result.lines.join('\n');

  // Generate status message similar to file reading
  let statusMessage = '';
  if (offset < 0) {
    // Tail read - match file reading format for consistency
    statusMessage = `[Reading last ${result.readCount} lines (total: ${result.totalLines} lines)]`;
  } else if (offset === 0) {
    // "New output" read
    if (result.remaining > 0) {
      statusMessage = `[Reading ${result.readCount} new lines from line ${result.readFrom} (total: ${result.totalLines} lines, ${result.remaining} remaining)]`;
    } else {
      statusMessage = `[Reading ${result.readCount} new lines (total: ${result.totalLines} lines)]`;
    }
  } else {
    // Absolute position read
    statusMessage = `[Reading ${result.readCount} lines from line ${result.readFrom} (total: ${result.totalLines} lines, ${result.remaining} remaining)]`;
  }

  // Surface buffer-cap eviction so the model knows the retained output is not
  // the full output and that line numbers shifted (matches the truncation
  // markers used by other tools).
  if (result.evictedLines && result.evictedLines > 0) {
    const capMB = Math.round(MAX_BUFFERED_OUTPUT_CHARS / 1024 / 1024);
    statusMessage += `\n[WARNING: output exceeded the ${capMB}MB buffer cap; the ${result.evictedLines} earliest lines were evicted and cannot be read. Line numbers and totals refer to the retained buffer only]`;
  }

  // Add process state info
  let processStateMessage = '';
  if (result.isComplete) {
    const runtimeStr = result.runtimeMs !== undefined 
      ? ` (runtime: ${(result.runtimeMs / 1000).toFixed(2)}s)` 
      : '';
    processStateMessage = `\n✅ Process completed with exit code ${result.exitCode}${runtimeStr}`;
  } else if (session) {
    // State detection only needs recent terminal context; avoid joining the
    // entire retained buffer (which can be tens of megabytes).
    const recentOutput = terminalManager.getOutputTail(pid);
    const processState = analyzeProcessState(recentOutput, pid);
    if (processState.isWaitingForInput) {
      processStateMessage = `\n🔄 ${formatProcessStateMessage(processState, pid)}`;
    }
  }

  // Add timing information if requested
  let timingMessage = '';
  if (verbose_timing) {
    const endTime = Date.now();
    timingMessage = `\n\n📊 Timing: ${endTime - startTime}ms`;
  }

  const responseText = output || '(No output in requested range)';

  return {
    content: [{
      type: "text",
      text: `${statusMessage}\n\n${responseText}${processStateMessage}${timingMessage}`
    }],
  };
}

/**
 * Interact with a running process (renamed from send_input)
 * Automatically detects when process is ready and returns output
 */
export async function interactWithProcess(args: unknown): Promise<ServerResult> {
  const parsed = InteractWithProcessArgsSchema.safeParse(args);
  if (!parsed.success) {
    capture('server_interact_with_process_failed', {
      error: 'Invalid arguments'
    });
    return {
      content: [{ type: "text", text: `Error: Invalid arguments for interact_with_process: ${parsed.error}` }],
      isError: true,
    };
  }

  const {
    pid,
    input,
    timeout_ms = 8000,
    wait_for_prompt = true,
    verbose_timing = false
  } = parsed.data;

  // Get config for output line limit and bounded process wait.
  const config = await configManager.getConfig();
  const maxOutputLines = config.fileReadLineLimit ?? 1000;
  const effectiveWaitMs = resolveProcessWaitMs(timeout_ms, config.maxProcessWaitMs);

  // Check if this is a virtual Node session (node:local)
  if (virtualNodeSessions.has(pid)) {
    const session = virtualNodeSessions.get(pid)!;
    capture('server_interact_with_process_node_fallback', {
      pid: pid,
      inputLength: input.length
    });

    // Execute code via temp file approach
    // Respect per-call timeout if provided, otherwise use session default
    const effectiveTimeout = timeout_ms ?? session.timeout_ms;
    return executeNodeCode(input, effectiveTimeout);
  }

  // Timing telemetry
  const startTime = Date.now();
  let firstOutputTime: number | undefined;
  let lastOutputTime: number | undefined;
  const outputEvents: any[] = [];
  let exitReason: 'early_exit_quick_pattern' | 'early_exit_event_state' | 'process_finished' | 'timeout' | 'no_wait' = 'timeout';

  try {
    capture('server_interact_with_process', {
      pid: pid,
      inputLength: input.length
    });

    // Capture output snapshot BEFORE sending input
    // This handles REPLs where output is appended to the prompt line
    const outputSnapshot = terminalManager.captureOutputSnapshot(pid);

    const success = terminalManager.sendInputToProcess(pid, input);

    if (!success) {
      return {
        content: [{ type: "text", text: `Error: Failed to send input to process ${pid}. The process may have exited or doesn't accept input.` }],
        isError: true,
      };
    }

    // If not waiting for response, return immediately
    if (!wait_for_prompt) {
      exitReason = 'no_wait';
      let timingMessage = '';
      if (verbose_timing) {
        const endTime = Date.now();
        const timingInfo = {
          startTime,
          endTime,
          totalDurationMs: endTime - startTime,
          exitReason,
          firstOutputTime,
          lastOutputTime,
          timeToFirstOutputMs: undefined,
          outputEvents: undefined
        };
        timingMessage = formatTimingInfo(timingInfo);
      }
      return {
        content: [{
          type: "text",
          text: `✅ Input sent to process ${pid}. Use read_process_output to get the response.${timingMessage}`
        }],
      };
    }

    // Wait for actual output/exit signals with one bounded deadline. The
    // original snapshot is retained for response extraction; a moving snapshot
    // is used only to await the next state change without busy looping.
    let output = "";
    let processState: ProcessState | undefined;
    let earlyExit = false;
    const quickPromptPatterns = />>>\s*$|>\s*$|\$\s*$|#\s*$/;
    const deadline = Date.now() + effectiveWaitMs;

    if (!outputSnapshot) {
      return {
        content: [{ type: "text", text: `Error: Process ${pid} is no longer active.` }],
        isError: true,
      };
    }

    let waitSnapshot = outputSnapshot;
    let observedTotalChars = outputSnapshot.totalChars;
    let promptExitReason: 'early_exit_quick_pattern' | 'early_exit_event_state' | null = null;

    while (true) {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        exitReason = 'timeout';
        break;
      }

      // Once a prompt is visible, wait for a short quiet period instead of
      // returning immediately. stdout/stderr are independent pipes, so useful
      // output from one stream may arrive just after the prompt on the other.
      // Any new process event resets this one-shot quiescence window.
      const waitMs = promptExitReason
        ? Math.min(remainingMs, REPL_PROMPT_QUIESCENCE_MS)
        : remainingMs;
      const change = await terminalManager.waitForSessionChange(
        pid,
        waitSnapshot,
        waitMs,
      );

      if (change === 'timeout') {
        if (promptExitReason) {
          earlyExit = true;
          exitReason = promptExitReason;
        } else {
          exitReason = 'timeout';
        }
        break;
      }

      const currentSnapshot = terminalManager.captureOutputSnapshot(pid);
      if (currentSnapshot && currentSnapshot.totalChars > observedTotalChars) {
        const now = Date.now();
        const deltaChars = currentSnapshot.totalChars - observedTotalChars;
        if (!firstOutputTime) firstOutputTime = now;
        lastOutputTime = now;
        observedTotalChars = currentSnapshot.totalChars;

        const recentOutput = terminalManager.getOutputTail(pid);
        if (verbose_timing) {
          outputEvents.push({
            timestamp: now,
            deltaMs: now - startTime,
            source: 'process_event',
            length: deltaChars,
            snippet: recentOutput.slice(-50).replace(/\n/g, '\\n')
          });
        }

        processState = analyzeProcessState(recentOutput, pid);
        if (quickPromptPatterns.test(recentOutput) || processState.isWaitingForInput) {
          promptExitReason = quickPromptPatterns.test(recentOutput)
            ? 'early_exit_quick_pattern'
            : 'early_exit_event_state';
          if (verbose_timing && outputEvents.length > 0) {
            outputEvents[outputEvents.length - 1].matchedPattern =
              promptExitReason === 'early_exit_quick_pattern' ? 'quick_pattern' : 'event_state';
          }
        }

        if (processState.isFinished) {
          exitReason = 'process_finished';
          break;
        }
      }

      if (change === 'exit') {
        processState = analyzeProcessState(terminalManager.getOutputTail(pid), pid);
        exitReason = 'process_finished';
        break;
      }

      if (!currentSnapshot) {
        exitReason = 'process_finished';
        break;
      }
      waitSnapshot = currentSnapshot;
    }

    // Materialize the interaction delta once after reconciliation, not on every
    // output event. This keeps event handling cheap while preserving response
    // compatibility for the final returned output.
    output = terminalManager.getOutputSinceSnapshot(pid, outputSnapshot) ?? '';

    // Clean and format output
    let cleanOutput = cleanProcessOutput(output, input);
    const timeoutReached = exitReason === 'timeout';
    
    // Apply output line limit to prevent context overflow
    let truncationMessage = '';
    const outputLines = cleanOutput.split('\n');
    if (outputLines.length > maxOutputLines) {
      const truncatedLines = outputLines.slice(0, maxOutputLines);
      cleanOutput = truncatedLines.join('\n');
      const remainingLines = outputLines.length - maxOutputLines;
      truncationMessage = `\n\n⚠️ Output truncated: showing ${maxOutputLines} of ${outputLines.length} lines (${remainingLines} hidden). Use read_process_output with offset/length for full output.`;
    }
    
    // Determine final state. If this interaction hit its bounded deadline
    // without producing new output, do not reclassify it from historical tail
    // content (for example, the prompt that existed before input was sent).
    if (!processState && !timeoutReached) {
      processState = analyzeProcessState(terminalManager.getOutputTail(pid), pid);
    }
    
    let statusMessage = '';
    if (timeoutReached) {
      statusMessage = '\n⏱️ Response may be incomplete (timeout reached)';
    } else if (processState?.isWaitingForInput) {
      statusMessage = `\n🔄 ${formatProcessStateMessage(processState, pid)}`;
    } else if (processState?.isFinished) {
      statusMessage = `\n✅ ${formatProcessStateMessage(processState, pid)}`;
    }

    // Add timing information if requested
    let timingMessage = '';
    if (verbose_timing) {
      const endTime = Date.now();
      const timingInfo = {
        startTime,
        endTime,
        totalDurationMs: endTime - startTime,
        exitReason,
        firstOutputTime,
        lastOutputTime,
        timeToFirstOutputMs: firstOutputTime ? firstOutputTime - startTime : undefined,
        outputEvents: outputEvents.length > 0 ? outputEvents : undefined
      };
      timingMessage = formatTimingInfo(timingInfo);
    }

    if (cleanOutput.trim().length === 0 && !timeoutReached) {
      return {
        content: [{
          type: "text",
          text: `✅ Input executed in process ${pid}.\n📭 (No output produced)${statusMessage}${timingMessage}`
        }],
      };
    }

    // Format response with better structure and consistent emojis
    let responseText = `✅ Input executed in process ${pid}`;

    if (cleanOutput && cleanOutput.trim().length > 0) {
      responseText += `:\n\n📤 Output:\n${cleanOutput}`;
    } else {
      responseText += `.\n📭 (No output produced)`;
    }

    if (statusMessage) {
      responseText += `\n\n${statusMessage}`;
    }

    if (truncationMessage) {
      responseText += truncationMessage;
    }

    if (timingMessage) {
      responseText += timingMessage;
    }

    return {
      content: [{
        type: "text",
        text: responseText
      }],
    };
    
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    capture('server_interact_with_process_error', {
      error: errorMessage
    });
    return {
      content: [{ type: "text", text: `Error interacting with process: ${errorMessage}` }],
      isError: true,
    };
  }
}

/**
 * Force terminate a process
 */
export async function forceTerminate(args: unknown): Promise<ServerResult> {
  const parsed = ForceTerminateArgsSchema.safeParse(args);
  if (!parsed.success) {
    return {
      content: [{ type: "text", text: `Error: Invalid arguments for force_terminate: ${parsed.error}` }],
      isError: true,
    };
  }

  const pid = parsed.data.pid;

  // Handle virtual Node.js sessions (node:local)
  if (virtualNodeSessions.has(pid)) {
    virtualNodeSessions.delete(pid);
    return {
      content: [{
        type: "text",
        text: `Cleared virtual Node.js session ${pid}`
      }],
    };
  }

  const success = terminalManager.forceTerminate(pid);
  return {
    content: [{
      type: "text",
      text: success
        ? `Successfully initiated termination of session ${pid}`
        : `No active session found for PID ${pid}`
    }],
  };
}

/**
 * List active sessions
 */
export async function listSessions(): Promise<ServerResult> {
  const sessions = terminalManager.listActiveSessions();

  // Include virtual Node.js sessions
  const virtualSessions = Array.from(virtualNodeSessions.entries()).map(([pid, session]) => ({
    pid,
    type: 'node:local',
    timeout_ms: session.timeout_ms
  }));

  const realSessionsText = sessions.map(s =>
    `PID: ${s.pid}, Blocked: ${s.isBlocked}, Runtime: ${Math.round(s.runtime / 1000)}s`
  );

  const virtualSessionsText = virtualSessions.map(s =>
    `PID: ${s.pid} (node:local), Timeout: ${s.timeout_ms}ms`
  );

  const allSessions = [...realSessionsText, ...virtualSessionsText];

  return {
    content: [{
      type: "text",
      text: allSessions.length === 0
        ? 'No active sessions'
        : allSessions.join('\n')
    }],
  };
}