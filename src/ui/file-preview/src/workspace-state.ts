import type { RenderPayload } from './model.js';
import { isPreviewStructuredContent } from './payload-utils.js';

export const WORKSPACE_STATE_VERSION = 1 as const;

export interface WorkspaceState {
    version: typeof WORKSPACE_STATE_VERSION;
    rootPath: string;
    currentPayload: RenderPayload;
    directoryBackPayload?: RenderPayload;
}

export type PersistedWorkspaceState = RenderPayload | WorkspaceState;

function isRenderPayload(value: unknown): value is RenderPayload {
    return isPreviewStructuredContent(value)
        && typeof (value as { content?: unknown }).content === 'string';
}

export function isWorkspaceState(value: unknown): value is WorkspaceState {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    const state = value as Partial<WorkspaceState>;
    const hasValidBackPayload = state.directoryBackPayload === undefined
        || (
            isRenderPayload(state.directoryBackPayload)
            && state.directoryBackPayload.fileType === 'directory'
            && state.directoryBackPayload.filePath === state.rootPath
        );
    return state.version === WORKSPACE_STATE_VERSION
        && typeof state.rootPath === 'string'
        && state.rootPath.length > 0
        && isRenderPayload(state.currentPayload)
        && hasValidBackPayload;
}

export function isPersistedWorkspaceState(value: unknown): value is PersistedWorkspaceState {
    return isRenderPayload(value) || isWorkspaceState(value);
}

export function createWorkspaceState(
    rootPath: string,
    currentPayload: RenderPayload,
    directoryBackPayload?: RenderPayload,
): WorkspaceState {
    if (!rootPath) {
        throw new Error('Workspace rootPath must not be empty.');
    }
    const backPayload = currentPayload.fileType === 'directory'
        ? undefined
        : directoryBackPayload;
    if (
        backPayload
        && (
            backPayload.fileType !== 'directory'
            || backPayload.filePath !== rootPath
        )
    ) {
        throw new Error('Workspace Back payload must be the root directory.');
    }
    return {
        version: WORKSPACE_STATE_VERSION,
        rootPath,
        currentPayload,
        ...(backPayload ? { directoryBackPayload: backPayload } : {}),
    };
}

export function normalizeWorkspaceState(value: unknown): WorkspaceState | undefined {
    if (isWorkspaceState(value)) {
        return createWorkspaceState(
            value.rootPath,
            value.currentPayload,
            value.directoryBackPayload,
        );
    }
    if (isRenderPayload(value)) {
        return createWorkspaceState(value.filePath, value);
    }
    return undefined;
}
