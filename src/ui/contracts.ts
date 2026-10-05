/**
 * Central constants and shape contracts for UI resource identifiers. It gives one source of truth for URIs/tool metadata shared between server handlers and UI loaders.
 */
export const FILE_PREVIEW_RESOURCE_URI = 'ui://desktop-commander/file-preview/v2';
export const CONFIG_EDITOR_RESOURCE_URI = 'ui://desktop-commander/config-editor/v2';

export interface UiToolMeta extends Record<string, unknown> {
  'ui/resourceUri': string;
  'openai/outputTemplate': string;
  ui: {
    resourceUri: string;
  };
}

export function buildUiToolMeta(resourceUri: string): UiToolMeta {
  return {
    'ui/resourceUri': resourceUri,
    'openai/outputTemplate': resourceUri,
    ui: {
      resourceUri,
    },
  };
}
