import {
    recordPresentationCoalesced,
    recordPresentationFrameScheduled,
    recordPresentationUpdate,
} from './presentation-metrics.js';

export interface LatestRenderSchedulerOptions<T> {
    schedule: (callback: () => void) => number;
    cancel: (id: number) => void;
    getCurrent: () => T | undefined;
    equivalent: (left: T | undefined, right: T | undefined) => boolean;
    render: (value: T | undefined) => void;
}

export interface LatestRenderScheduler<T> {
    enqueue: (value: T | undefined) => void;
    cancel: () => void;
}

export function createLatestRenderScheduler<T>(
    options: LatestRenderSchedulerOptions<T>,
): LatestRenderScheduler<T> {
    let frameId: number | undefined;
    let hasPending = false;
    let pending: T | undefined;

    const flush = (): void => {
        frameId = undefined;
        if (!hasPending) {
            return;
        }

        const value = pending;
        pending = undefined;
        hasPending = false;

        if (options.equivalent(options.getCurrent(), value)) {
            recordPresentationCoalesced();
            return;
        }

        options.render(value);
    };

    return {
        enqueue(value): void {
            recordPresentationUpdate();

            if (!hasPending && options.equivalent(options.getCurrent(), value)) {
                recordPresentationCoalesced();
                return;
            }

            if (hasPending) {
                recordPresentationCoalesced();
            }

            pending = value;
            hasPending = true;

            if (frameId === undefined) {
                recordPresentationFrameScheduled();
                frameId = options.schedule(flush);
            }
        },
        cancel(): void {
            if (frameId !== undefined) {
                options.cancel(frameId);
                frameId = undefined;
            }
            pending = undefined;
            hasPending = false;
        },
    };
}
