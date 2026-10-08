export interface PresentationMetrics {
    mounts: number;
    renderCalls: number;
    updatesReceived: number;
    updatesCoalesced: number;
    framesScheduled: number;
}

const metrics: PresentationMetrics = {
    mounts: 0,
    renderCalls: 0,
    updatesReceived: 0,
    updatesCoalesced: 0,
    framesScheduled: 0,
};

export function recordPresentationMount(): void {
    metrics.mounts += 1;
}

export function recordPresentationRender(): void {
    metrics.renderCalls += 1;
}

export function recordPresentationUpdate(): void {
    metrics.updatesReceived += 1;
}

export function recordPresentationCoalesced(): void {
    metrics.updatesCoalesced += 1;
}

export function recordPresentationFrameScheduled(): void {
    metrics.framesScheduled += 1;
}

export function getPresentationMetrics(): PresentationMetrics {
    return { ...metrics };
}

export function resetPresentationMetrics(): void {
    metrics.mounts = 0;
    metrics.renderCalls = 0;
    metrics.updatesReceived = 0;
    metrics.updatesCoalesced = 0;
    metrics.framesScheduled = 0;
}
