import { 
    startProcess, 
    readProcessOutput, 
    interactWithProcess,
    forceTerminate, 
    listSessions 
} from '../tools/improved-process-tools.js';

import { 
    StartProcessArgsSchema,
    ReadProcessOutputArgsSchema,
    InteractWithProcessArgsSchema,
    ForceTerminateArgsSchema,
    ListSessionsArgsSchema
} from '../tools/schemas.js';

import { ServerResult, type ToolExecutionContext } from '../types.js';

/**
 * Handle start_process command (improved execute_command)
 */
export async function handleStartProcess(
    args: unknown,
    context?: ToolExecutionContext,
): Promise<ServerResult> {
    const parsed = StartProcessArgsSchema.parse(args);
    return startProcess(parsed, context);
}

/**
 * Handle read_process_output command (improved read_output)
 */
export async function handleReadProcessOutput(
    args: unknown,
    context?: ToolExecutionContext,
): Promise<ServerResult> {
    const parsed = ReadProcessOutputArgsSchema.parse(args);
    return readProcessOutput(parsed, context);
}

/**
 * Handle interact_with_process command (improved send_input)
 */
export async function handleInteractWithProcess(args: unknown): Promise<ServerResult> {
    return interactWithProcess(args);
}

/**
 * Handle force_terminate command
 */
export async function handleForceTerminate(args: unknown): Promise<ServerResult> {
    const parsed = ForceTerminateArgsSchema.parse(args);
    return forceTerminate(parsed);
}

/**
 * Handle list_sessions command
 */
export async function handleListSessions(): Promise<ServerResult> {
    return listSessions();
}