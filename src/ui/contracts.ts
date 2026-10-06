/**
 * Central constants and shape contracts for UI resource identifiers. It gives one source of truth for URIs/tool metadata shared between server handlers and UI loaders.
 */
export const FILE_PREVIEW_RESOURCE_URI = 'ui://desktop-commander/file-preview/v2';
export const CONFIG_EDITOR_RESOURCE_URI = 'ui://desktop-commander/config-editor/v2';

export type UiToolVisibility = 'model' | 'app';

export interface UiToolMeta extends Record<string, unknown> {
  'openai/outputTemplate': string;
  ui: {
    resourceUri: string;
    visibility: UiToolVisibility[];
  };
}

export function buildUiToolMeta(
  resourceUri: string,
  visibility: UiToolVisibility[] = ['model', 'app'],
): UiToolMeta {
  return {
    'openai/outputTemplate': resourceUri,
    ui: {
      resourceUri,
      visibility,
    },
  };
}
