import { toolHistory } from '../utils/toolHistory.js';
import { GetRecentToolCallsArgsSchema, TrackUiEventArgsSchema } from '../tools/schemas.js';
import { ServerResult } from '../types.js';
import { capture_ui_event } from '../utils/capture.js';

type TrackUiEventParams = Record<string, string | number | boolean | null>;

export function buildTrackUiEventCapturePayload(event: string, component: string, params: TrackUiEventParams): Record<string, string | number | boolean | null> {
  return {
    ...params,
    component,
    event
  };
}

/**
 * Handle get_recent_tool_calls command
 */
export async function handleGetRecentToolCalls(args: unknown): Promise<ServerResult> {
  try {
    const parsed = GetRecentToolCallsArgsSchema.parse(args);
    
    // Use formatted version with local timezone
    const calls = toolHistory.getRecentCallsFormatted({
      maxResults: parsed.maxResults,
      toolName: parsed.toolName,
      since: parsed.since
    });
    
    const stats = toolHistory.getStats();
    
    // Format the response (excluding file path per user request)
    const summary = `Tool Call History (${calls.length} results, ${stats.totalEntries} total in memory)`;
    const historyJson = JSON.stringify(calls, null, 2);
    
    return {
      content: [{
        type: "text",
        text: `${summary}\n\n${historyJson}`
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: `Error getting tool history: ${error instanceof Error ? error.message : String(error)}`
      }],
      isError: true
    };
  }
}

/**
 * Handle track_ui_event command
 */
export async function handleTrackUiEvent(args: unknown): Promise<ServerResult> {
  try {
    const parsed = TrackUiEventArgsSchema.parse(args);
    const events = parsed.events ?? [{
      event: parsed.event!,
      component: parsed.component ?? 'file_preview',
      params: parsed.params ?? {},
    }];

    await Promise.all(events.map((event) =>
      capture_ui_event(
        'mcp_ui_event',
        buildTrackUiEventCapturePayload(event.event, event.component, event.params),
      )
    ));

    return {
      content: [{
        type: "text",
        text: events.length === 1
          ? `Tracked UI event: ${events[0].event}`
          : `Tracked ${events.length} UI events`,
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: `Error tracking UI event: ${error instanceof Error ? error.message : String(error)}`
      }],
      isError: true
    };
  }
}
