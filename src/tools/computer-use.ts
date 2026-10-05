import net from 'node:net';
import { z } from 'zod';
import type { ServerResult } from '../types.js';
import { ComputerInspectArgsSchema } from './schemas.js';

const PIPE_PATH = '\\\\.\\pipe\\DesktopCommander.UiBridge.v1';
const RESPONSE_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 12 * 1024 * 1024;

const RectSchema = z.object({
    x: z.number().int(),
    y: z.number().int(),
    width: z.number().int().nonnegative(),
    height: z.number().int().nonnegative(),
});

const HealthSchema = z.object({
    protocolVersion: z.literal('1'),
    processId: z.number().int().positive(),
    sessionId: z.number().int().nonnegative(),
    userName: z.string().min(1).max(256),
    userInteractive: z.boolean(),
    foregroundWindowAvailable: z.boolean(),
    ready: z.boolean(),
});

const UiElementSchema = z.object({
    id: z.string().min(1).max(64),
    name: z.string().max(4096).nullable(),
    automationId: z.string().max(4096).nullable(),
    controlType: z.string().min(1).max(128),
    className: z.string().max(1024).nullable(),
    enabled: z.boolean(),
    offscreen: z.boolean(),
    keyboardFocusable: z.boolean(),
    hasKeyboardFocus: z.boolean(),
    bounds: RectSchema,
    patterns: z.array(z.string().min(1).max(256)).max(64),
    depth: z.number().int().min(0).max(8),
    parentId: z.string().max(64).nullable(),
});

const ScreenshotSchema = z.object({
    mimeType: z.literal('image/png'),
    data: z.string().min(1).max(11 * 1024 * 1024),
    width: z.number().int().positive().max(1920),
    height: z.number().int().positive().max(4320),
});

const SnapshotSchema = z.object({
    snapshotId: z.string().regex(/^[a-f0-9]{32}$/),
    capturedAt: z.string().datetime({ offset: true }),
    sessionId: z.number().int().positive(),
    foregroundProcessId: z.number().int().nonnegative(),
    foregroundProcessName: z.string().max(1024).nullable(),
    foregroundTitle: z.string().max(4096).nullable(),
    foregroundBounds: RectSchema,
    truncated: z.boolean(),
    elements: z.array(UiElementSchema).max(500),
    screenshot: ScreenshotSchema.nullable(),
});

const ErrorSchema = z.object({
    code: z.string().min(1).max(128),
    message: z.string().min(1).max(1024),
});

const EnvelopeSchema = z.object({
    ok: z.boolean(),
    data: z.unknown().nullable().optional(),
    error: ErrorSchema.nullable().optional(),
});

type Snapshot = z.infer<typeof SnapshotSchema>;

function errorResult(code: string, message: string): ServerResult {
    const payload = { error: { code, message } };
    return {
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        structuredContent: payload,
        isError: true,
    };
}

function textResult(payload: Record<string, unknown>): ServerResult {
    return {
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        structuredContent: payload,
    };
}

function snapshotResult(snapshot: Snapshot): ServerResult {
    const { screenshot, ...rest } = snapshot;
    const screenshotMetadata = screenshot
        ? {
              mimeType: screenshot.mimeType,
              width: screenshot.width,
              height: screenshot.height,
              byteLength: Buffer.from(screenshot.data, 'base64').byteLength,
          }
        : null;
    const structured = { ...rest, screenshot: screenshotMetadata };

    return {
        content: [
            { type: 'text', text: JSON.stringify(structured) },
            ...(screenshot
                ? [{ type: 'image', data: screenshot.data, mimeType: screenshot.mimeType }]
                : []),
        ],
        structuredContent: structured,
    };
}

async function requestUiBridge(payload: Record<string, unknown>): Promise<unknown> {
    if (process.platform !== 'win32') {
        throw new Error('WINDOWS_REQUIRED');
    }

    return new Promise((resolve, reject) => {
        const socket = net.createConnection(PIPE_PATH);
        const chunks: Buffer[] = [];
        let totalBytes = 0;
        let settled = false;

        const finish = (callback: () => void) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            socket.removeAllListeners();
            socket.destroy();
            callback();
        };

        const timer = setTimeout(() => {
            finish(() => reject(new Error('UI_BRIDGE_TIMEOUT')));
        }, RESPONSE_TIMEOUT_MS);

        socket.on('connect', () => {
            socket.write(JSON.stringify(payload) + '\n', 'utf8');
        });

        socket.on('data', (chunk: Buffer) => {
            totalBytes += chunk.byteLength;
            if (totalBytes > MAX_RESPONSE_BYTES) {
                finish(() => reject(new Error('UI_BRIDGE_RESPONSE_TOO_LARGE')));
                return;
            }

            chunks.push(chunk);
            const buffer = Buffer.concat(chunks);
            const newline = buffer.indexOf(0x0a);
            if (newline < 0) return;

            const line = buffer.subarray(0, newline).toString('utf8');
            finish(() => {
                try {
                    resolve(JSON.parse(line));
                } catch {
                    reject(new Error('UI_BRIDGE_INVALID_JSON'));
                }
            });
        });

        socket.on('error', () => {
            finish(() => reject(new Error('UI_BRIDGE_UNAVAILABLE')));
        });

        socket.on('end', () => {
            if (!settled) {
                finish(() => reject(new Error('UI_BRIDGE_CLOSED')));
            }
        });
    });
}

export async function handleComputerInspect(args: unknown): Promise<ServerResult> {
    const parsed = ComputerInspectArgsSchema.safeParse(args);
    if (!parsed.success) {
        return errorResult('INVALID_INPUT', 'Computer inspection arguments are invalid.');
    }

    const input = parsed.data;
    const request =
        input.action === 'health'
            ? { method: 'health' }
            : {
                  method: 'snapshot',
                  maxDepth: input.maxDepth,
                  maxElements: input.maxElements,
                  includeScreenshot: input.includeScreenshot,
                  screenshotMaxWidth: input.screenshotMaxWidth,
              };

    let raw: unknown;
    try {
        raw = await requestUiBridge(request);
    } catch (error) {
        const code = error instanceof Error ? error.message : 'UI_BRIDGE_FAILURE';
        const safeCode = code.startsWith('UI_BRIDGE_') || code === 'WINDOWS_REQUIRED'
            ? code
            : 'UI_BRIDGE_FAILURE';
        const message =
            safeCode === 'WINDOWS_REQUIRED'
                ? 'Computer inspection is available only on Windows.'
                : 'The interactive UI bridge is unavailable or did not respond safely.';
        return errorResult(safeCode, message);
    }

    const envelope = EnvelopeSchema.safeParse(raw);
    if (!envelope.success) {
        return errorResult('UI_BRIDGE_PROTOCOL_ERROR', 'The interactive UI bridge returned an invalid response.');
    }

    if (!envelope.data.ok) {
        const bridgeError = envelope.data.error;
        return errorResult(
            bridgeError?.code ?? 'UI_BRIDGE_FAILURE',
            bridgeError?.message ?? 'The interactive UI bridge rejected the request.',
        );
    }

    if (input.action === 'health') {
        const health = HealthSchema.safeParse(envelope.data.data);
        if (!health.success) {
            return errorResult('UI_BRIDGE_PROTOCOL_ERROR', 'The UI bridge health response is invalid.');
        }
        return textResult(health.data);
    }

    const snapshot = SnapshotSchema.safeParse(envelope.data.data);
    if (!snapshot.success) {
        return errorResult('UI_BRIDGE_PROTOCOL_ERROR', 'The UI bridge snapshot response is invalid.');
    }

    return snapshotResult(snapshot.data);
}
