import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';
import type { ServerResult, ToolExecutionContext } from '../types.js';
import { OpenCodeReadArgsSchema, OpenCodeTaskArgsSchema } from './schemas.js';

const BridgeTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43,256}$/);
const ProjectSchema = z.string().regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/);
const SessionSchema = z.string().min(1).max(256);
const TaskStateSchema = z.enum(['queued', 'running', 'completed', 'failed', 'aborted']);

const ErrorEnvelopeSchema = z.object({
    error: z.object({
        code: z.string().min(1).max(128),
        message: z.string().min(1).max(512),
    }),
});
const HealthSchema = z.object({
    gateway: z.literal('ok'),
    opencode: z.unknown().optional(),
    projectCount: z.number().int().nonnegative().optional(),
});
const ProjectsSchema = z.object({ projects: z.array(ProjectSchema) });
const SessionsSchema = z.object({
    project: ProjectSchema,
    result: z.object({
        sessions: z.array(z.object({
            id: SessionSchema,
            updatedAt: z.number().nonnegative(),
            active: z.boolean(),
        })),
    }),
});
const StartSchema = z.object({ project: ProjectSchema, sessionId: SessionSchema });
const ContinueSchema = z.object({
    accepted: z.literal(true),
    project: ProjectSchema,
    sessionId: SessionSchema,
});
const StatusSchema = z.object({
    project: ProjectSchema,
    sessionId: SessionSchema,
    result: z.object({
        state: TaskStateSchema,
        messageCount: z.number().int().nonnegative(),
    }),
});
const MessagesSchema = z.object({
    project: ProjectSchema,
    sessionId: SessionSchema,
    result: z.object({
        messages: z.array(z.object({
            role: z.literal('assistant'),
            completed: z.boolean(),
            failed: z.boolean(),
            aborted: z.boolean(),
            text: z.string(),
        })),
    }),
});
const DiffSchema = z.object({
    project: ProjectSchema,
    sessionId: SessionSchema,
    result: z.unknown(),
});
const AbortSchema = z.object({
    project: ProjectSchema,
    sessionId: SessionSchema,
    aborted: z.boolean(),
});

type McpToolResult = Awaited<ReturnType<Client['callTool']>>;

function asServerResult(payload: Record<string, unknown>, isError = false): ServerResult {
    return {
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        structuredContent: payload,
        ...(isError ? { isError: true } : {}),
    };
}

function structured(result: McpToolResult): Record<string, unknown> {
    if (result.isError) {
        const parsed = ErrorEnvelopeSchema.safeParse(result.structuredContent);
        if (parsed.success) {
            throw new Error(
                'OpenCode gateway ' + parsed.data.error.code + ': ' + parsed.data.error.message,
            );
        }
        throw new Error('OpenCode gateway returned an error');
    }
    const value = result.structuredContent;
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('OpenCode gateway returned invalid structured content');
    }
    return value as Record<string, unknown>;
}

async function loadGatewayOptions(
    env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<{ url: URL; token: string }> {
    const rawUrl = env.OPENCODE_GATEWAY_RDC_URL ?? 'http://127.0.0.1:8787/rdc-mcp';
    let url: URL;
    try {
        url = new URL(rawUrl);
    } catch {
        throw new Error('OpenCode gateway URL is invalid');
    }

    const host = url.hostname.toLowerCase();
    if (
        url.protocol !== 'http:' ||
        !['127.0.0.1', 'localhost', '[::1]'].includes(host) ||
        url.pathname !== '/rdc-mcp' ||
        url.username !== '' ||
        url.password !== '' ||
        url.search !== '' ||
        url.hash !== ''
    ) {
        throw new Error('OpenCode gateway must use loopback HTTP /rdc-mcp');
    }

    let rawToken = env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
    if (rawToken === undefined) {
        const programData =
            env.ProgramData ??
            env.ALLUSERSPROFILE ??
            (env.SystemDrive ? join(env.SystemDrive, 'ProgramData') : undefined);
        const tokenFile =
            env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN_FILE ??
            (programData
                ? join(programData, 'ChatGPT-OpenCode', 'MCP', 'rdc-bridge.token')
                : undefined);
        if (!tokenFile) throw new Error('OpenCode gateway token is unavailable');
        try {
            rawToken = (await readFile(tokenFile, 'utf8')).trim();
        } catch {
            throw new Error('OpenCode gateway token is unavailable');
        }
    }

    return { url, token: BridgeTokenSchema.parse(rawToken) };
}

async function withGateway<T>(operation: (client: Client) => Promise<T>): Promise<T> {
    const { url, token } = await loadGatewayOptions();
    const client = new Client({
        name: 'desktop-commander-opencode',
        version: '0.1.0',
    });
    const transport = new StreamableHTTPClientTransport(url, {
        requestInit: {
            headers: { Authorization: 'Bearer ' + token },
        },
        redirectPolicy: 'same-origin',
    });

    try {
        await client.connect(transport);
        return await operation(client);
    } finally {
        await client.close().catch(() => undefined);
    }
}

type GatewayCallOptions = {
    signal?: AbortSignal;
    timeout?: number;
};

async function callGateway(
    client: Client,
    name: string,
    args: Record<string, unknown>,
    options?: GatewayCallOptions,
): Promise<Record<string, unknown>> {
    const response = structured(
        await client.callTool(
            { name, arguments: args },
            undefined,
            options,
        ),
    );
    // Bind every scoped response to the selector that JDC actually sent.
    // A structurally valid response for another project/session is not safe.
    if (typeof args.project === 'string' && response.project !== args.project) {
        throw new Error('OpenCode gateway response project mismatch');
    }
    if (typeof args.sessionId === 'string' && response.sessionId !== args.sessionId) {
        throw new Error('OpenCode gateway response session mismatch');
    }
    return response;
}

async function finalTaskResult(
    client: Client,
    action: 'run' | 'continue',
    project: string,
    sessionId: string,
    timeoutMs: number,
    context: ToolExecutionContext,
): Promise<ServerResult> {
    const status = StatusSchema.parse(
        await callGateway(
            client,
            'task_wait',
            { project, sessionId },
            {
                ...(context.signal === undefined ? {} : { signal: context.signal }),
                timeout: timeoutMs,
            },
        ),
    );
    const messages = MessagesSchema.parse(
        await callGateway(
            client,
            'task_messages',
            { project, sessionId },
            context.signal === undefined ? undefined : { signal: context.signal },
        ),
    );
    const latestAssistant =
        messages.result.messages.length > 0
            ? messages.result.messages[messages.result.messages.length - 1]
            : null;
    const payload: Record<string, unknown> = {
        action,
        project,
        sessionId,
        state: status.result.state,
        messageCount: status.result.messageCount,
        latestAssistant,
    };
    return asServerResult(
        payload,
        status.result.state === 'failed' || status.result.state === 'aborted',
    );
}

export async function handleOpenCodeRead(rawArgs: unknown): Promise<ServerResult> {
    const input = OpenCodeReadArgsSchema.parse(rawArgs ?? {});
    return withGateway(async (client) => {
        switch (input.action) {
            case 'health':
                return asServerResult(
                    HealthSchema.parse(await callGateway(client, 'gateway_health', {})),
                );
            case 'projects':
                return asServerResult(
                    ProjectsSchema.parse(await callGateway(client, 'project_list', {})),
                );
            case 'sessions': {
                const value = SessionsSchema.parse(
                    await callGateway(client, 'task_sessions', { project: input.project }),
                );
                return asServerResult(value);
            }
            case 'status':
                return asServerResult(
                    StatusSchema.parse(
                        await callGateway(client, 'task_status', {
                            project: input.project,
                            sessionId: input.sessionId,
                        }),
                    ),
                );
            case 'messages': {
                const value = MessagesSchema.parse(
                    await callGateway(client, 'task_messages', {
                        project: input.project,
                        sessionId: input.sessionId,
                    }),
                );
                const offset = input.offset ?? 0;
                return asServerResult({
                    ...value,
                    result: { messages: value.result.messages.slice(offset) },
                });
            }
            case 'diff':
                return asServerResult(
                    DiffSchema.parse(
                        await callGateway(client, 'task_diff', {
                            project: input.project,
                            sessionId: input.sessionId,
                        }),
                    ),
                );
        }
    });
}

export async function handleOpenCodeTask(
    rawArgs: unknown,
    context: ToolExecutionContext = {},
): Promise<ServerResult> {
    const input = OpenCodeTaskArgsSchema.parse(rawArgs ?? {});
    const timeoutMs = input.timeout_ms ?? 180000;

    return withGateway(async (client) => {
        switch (input.action) {
            case 'start': {
                const prompt = input.prompt;
                if (!prompt) throw new Error('prompt is required for start');
                const args: Record<string, unknown> = {
                    project: input.project,
                    prompt,
                };
                if (input.agent) args.agent = input.agent;
                return asServerResult(
                    StartSchema.parse(
                        await callGateway(
                            client,
                            'task_start',
                            args,
                            context.signal === undefined ? undefined : { signal: context.signal },
                        ),
                    ),
                );
            }
            case 'run': {
                const prompt = input.prompt;
                if (!prompt) throw new Error('prompt is required for run');
                const args: Record<string, unknown> = {
                    project: input.project,
                    prompt,
                };
                if (input.agent) args.agent = input.agent;
                const started = StartSchema.parse(
                    await callGateway(
                        client,
                        'task_start',
                        args,
                        context.signal === undefined ? undefined : { signal: context.signal },
                    ),
                );
                return finalTaskResult(
                    client,
                    'run',
                    input.project,
                    started.sessionId,
                    timeoutMs,
                    context,
                );
            }
            case 'continue': {
                const sessionId = input.sessionId;
                const prompt = input.prompt;
                if (!sessionId) throw new Error('sessionId is required for continue');
                if (!prompt) throw new Error('prompt is required for continue');
                const args: Record<string, unknown> = {
                    project: input.project,
                    sessionId,
                    prompt,
                };
                if (input.agent) args.agent = input.agent;
                ContinueSchema.parse(
                    await callGateway(
                        client,
                        'task_continue',
                        args,
                        context.signal === undefined ? undefined : { signal: context.signal },
                    ),
                );
                return finalTaskResult(
                    client,
                    'continue',
                    input.project,
                    sessionId,
                    timeoutMs,
                    context,
                );
            }
            case 'abort': {
                const sessionId = input.sessionId;
                if (!sessionId) throw new Error('sessionId is required for abort');
                return asServerResult(
                    AbortSchema.parse(
                        await callGateway(
                            client,
                            'task_abort',
                            {
                                project: input.project,
                                sessionId,
                            },
                            context.signal === undefined ? undefined : { signal: context.signal },
                        ),
                    ),
                );
            }
        }
    });
}
