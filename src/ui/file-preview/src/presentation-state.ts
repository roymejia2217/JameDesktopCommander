import type { RenderPayload } from './model.js';

export const MARKDOWN_EDITOR_CACHE_LIMIT = 32;

export function areRenderPayloadsEquivalent(
    current: RenderPayload | undefined,
    incoming: RenderPayload | undefined,
): boolean {
    if (current === incoming) {
        return true;
    }
    if (!current || !incoming) {
        return false;
    }

    return current.fileName === incoming.fileName
        && current.filePath === incoming.filePath
        && current.fileType === incoming.fileType
        && current.sourceTool === incoming.sourceTool
        && current.defaultEditorName === incoming.defaultEditorName
        && current.defaultEditorPath === incoming.defaultEditorPath
        && current.content === incoming.content
        && current.mimeType === incoming.mimeType;
}

export function setBoundedMapEntry<K, V>(
    cache: Map<K, V>,
    key: K,
    value: V,
    maxEntries = MARKDOWN_EDITOR_CACHE_LIMIT,
): void {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
        throw new RangeError('maxEntries must be a positive integer');
    }

    if (cache.has(key)) {
        cache.delete(key);
    }
    cache.set(key, value);

    while (cache.size > maxEntries) {
        const oldest = cache.keys().next();
        if (oldest.done) {
            return;
        }
        cache.delete(oldest.value);
    }
}
