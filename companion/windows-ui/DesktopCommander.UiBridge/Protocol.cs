using System.Text.Json.Serialization;

namespace DesktopCommander.UiBridge;

internal sealed record BridgeRequest
{
    [JsonPropertyName("method")]
    public string Method { get; init; } = string.Empty;

    [JsonPropertyName("maxDepth")]
    public int? MaxDepth { get; init; }

    [JsonPropertyName("maxElements")]
    public int? MaxElements { get; init; }

    [JsonPropertyName("includeScreenshot")]
    public bool? IncludeScreenshot { get; init; }

    [JsonPropertyName("screenshotMaxWidth")]
    public int? ScreenshotMaxWidth { get; init; }
}

internal sealed record BridgeEnvelope(bool Ok, object? Data = null, BridgeError? Error = null)
{
    public static BridgeEnvelope Success(object data) => new(true, data, null);

    public static BridgeEnvelope Failure(string code, string message) =>
        new(false, null, new BridgeError(code, message));
}

internal sealed record BridgeError(string Code, string Message);

internal sealed record RectDto(int X, int Y, int Width, int Height);

internal sealed record UiElementDto(
    string Id,
    string? Name,
    string? AutomationId,
    string ControlType,
    string? ClassName,
    bool Enabled,
    bool Offscreen,
    bool KeyboardFocusable,
    bool HasKeyboardFocus,
    RectDto Bounds,
    IReadOnlyList<string> Patterns,
    int Depth,
    string? ParentId);

internal sealed record ScreenshotDto(
    string MimeType,
    string Data,
    int Width,
    int Height);

internal sealed record SnapshotDto(
    string SnapshotId,
    DateTimeOffset CapturedAt,
    int SessionId,
    int ForegroundProcessId,
    string? ForegroundProcessName,
    string? ForegroundTitle,
    RectDto ForegroundBounds,
    bool Truncated,
    IReadOnlyList<UiElementDto> Elements,
    ScreenshotDto? Screenshot);

internal sealed record HealthDto(
    string ProtocolVersion,
    int ProcessId,
    int SessionId,
    string UserName,
    bool UserInteractive,
    bool ForegroundWindowAvailable,
    bool Ready);
