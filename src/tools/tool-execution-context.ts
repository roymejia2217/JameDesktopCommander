import type { ToolExecutionContext } from '../types.js';

interface McpToolHandlerExtra {
  signal: AbortSignal;
  _meta?: {
    progressToken?: string | number;
  };
  sendNotification(notification: {
    method: 'notifications/progress';
    params: {
      progressToken: string | number;
      progress: number;
      total?: number;
      message?: string;
    };
  }): Promise<void>;
}

export function createToolExecutionContext(
  extra: McpToolHandlerExtra,
): ToolExecutionContext {
  const progressToken = extra._meta?.progressToken;
  let lastProgress = -1;
  let notificationChain: Promise<void> = Promise.resolve();

  if (progressToken === undefined) {
    return { signal: extra.signal };
  }

  return {
    signal: extra.signal,
    reportProgress: async (update) => {
      const progress = Math.max(lastProgress + 1, update.progress);
      lastProgress = progress;

      notificationChain = notificationChain
        .then(async () => {
          if (extra.signal.aborted) return;
          await extra.sendNotification({
            method: 'notifications/progress',
            params: {
              progressToken,
              progress,
              ...(update.total !== undefined ? { total: update.total } : {}),
              ...(update.message !== undefined ? { message: update.message } : {}),
            },
          });
        })
        .catch(() => undefined);

      await notificationChain;
    },
  };
}
