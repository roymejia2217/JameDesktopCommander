type UiEventParamValue = string | number | boolean | null;

export type UiEventParams = Record<string, UiEventParamValue>;

type ToolCaller = (name: string, args: Record<string, unknown>) => Promise<unknown>;

export interface UiEventTrackerOptions {
    component: string;
    baseParams?: UiEventParams;
    scheduleFlush?: (callback: () => void) => void;
    maxPendingEvents?: number;
}

export interface UiEventTrackerMetrics {
    queued: number;
    coalesced: number;
    dropped: number;
    batchesSent: number;
    eventsSent: number;
}

export interface UiEventTracker {
    (event: string, params?: Record<string, unknown>): void;
    flush: () => Promise<void>;
    cancel: () => void;
    getMetrics: () => UiEventTrackerMetrics;
}

interface PendingUiEvent {
    event: string;
    component: string;
    params: UiEventParams;
}

const DEFAULT_MAX_PENDING_EVENTS = 32;

function normalizeUiEventParams(params: Record<string, unknown> | undefined): UiEventParams {
    const normalized: UiEventParams = {};

    if (!params) {
        return normalized;
    }

    for (const [key, value] of Object.entries(params)) {
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
            normalized[key] = value;
        }
    }

    return normalized;
}

function buildEventKey(event: PendingUiEvent): string {
    const sortedParams = Object.keys(event.params)
        .sort()
        .map((key) => [key, event.params[key]]);
    return JSON.stringify([event.event, event.component, sortedParams]);
}

function defaultScheduleFlush(callback: () => void): void {
    if (typeof globalThis.requestAnimationFrame === 'function') {
        globalThis.requestAnimationFrame(() => callback());
        return;
    }
    queueMicrotask(callback);
}

export function createUiEventTracker(callTool: ToolCaller, options: UiEventTrackerOptions): UiEventTracker {
    const baseParams = options.baseParams ?? {};
    const scheduleFlush = options.scheduleFlush ?? defaultScheduleFlush;
    const maxPendingEvents = Math.max(1, Math.floor(options.maxPendingEvents ?? DEFAULT_MAX_PENDING_EVENTS));
    const pending = new Map<string, PendingUiEvent>();
    const metrics: UiEventTrackerMetrics = {
        queued: 0,
        coalesced: 0,
        dropped: 0,
        batchesSent: 0,
        eventsSent: 0,
    };
    let flushScheduled = false;

    const flush = async (): Promise<void> => {
        flushScheduled = false;
        if (pending.size === 0) {
            return;
        }

        const events = [...pending.values()];
        pending.clear();

        try {
            if (events.length === 1) {
                const [single] = events;
                await callTool('track_ui_event', {
                    event: single.event,
                    component: single.component,
                    params: single.params,
                });
            } else {
                await callTool('track_ui_event', { events });
            }
            metrics.batchesSent += 1;
            metrics.eventsSent += events.length;
        } catch {
            // UI analytics should never block UI interactions.
        }
    };

    const tracker = ((event: string, params: Record<string, unknown> = {}): void => {
        const next: PendingUiEvent = {
            event,
            component: options.component,
            params: {
                ...baseParams,
                ...normalizeUiEventParams(params),
            },
        };
        metrics.queued += 1;

        const key = buildEventKey(next);
        if (pending.has(key)) {
            metrics.coalesced += 1;
            return;
        }

        if (pending.size >= maxPendingEvents) {
            const oldestKey = pending.keys().next().value as string | undefined;
            if (oldestKey !== undefined) {
                pending.delete(oldestKey);
                metrics.dropped += 1;
            }
        }
        pending.set(key, next);

        if (!flushScheduled) {
            flushScheduled = true;
            scheduleFlush(() => {
                void flush();
            });
        }
    }) as UiEventTracker;

    tracker.flush = flush;
    tracker.cancel = (): void => {
        pending.clear();
        flushScheduled = false;
    };
    tracker.getMetrics = (): UiEventTrackerMetrics => ({ ...metrics });

    return tracker;
}
