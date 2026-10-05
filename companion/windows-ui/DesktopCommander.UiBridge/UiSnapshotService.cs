using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Capturing;
using FlaUI.UIA3;

namespace DesktopCommander.UiBridge;

internal sealed partial class UiSnapshotService
{
    private const int DefaultMaxDepth = 6;
    private const int DefaultMaxElements = 300;
    private const int DefaultScreenshotMaxWidth = 1440;

    public HealthDto GetHealth()
    {
        var foreground = NativeMethods.GetForegroundWindow();
        var sessionId = Process.GetCurrentProcess().SessionId;
        var ready = Environment.UserInteractive && sessionId > 0 && foreground != nint.Zero;

        return new HealthDto(
            ProtocolVersion: "1",
            ProcessId: Environment.ProcessId,
            SessionId: sessionId,
            UserName: Environment.UserName,
            UserInteractive: Environment.UserInteractive,
            ForegroundWindowAvailable: foreground != nint.Zero,
            Ready: ready);
    }

    public SnapshotDto Capture(BridgeRequest request)
    {
        var maxDepth = Clamp(request.MaxDepth ?? DefaultMaxDepth, 1, 8, nameof(request.MaxDepth));
        var maxElements = Clamp(request.MaxElements ?? DefaultMaxElements, 1, 500, nameof(request.MaxElements));
        var screenshotMaxWidth = Clamp(
            request.ScreenshotMaxWidth ?? DefaultScreenshotMaxWidth,
            320,
            1920,
            nameof(request.ScreenshotMaxWidth));
        var includeScreenshot = request.IncludeScreenshot ?? true;

        var health = GetHealth();
        if (!health.Ready)
        {
            throw new BridgeException(
                "INTERACTIVE_SESSION_UNAVAILABLE",
                "The UI bridge is not running in an interactive Windows user session.");
        }

        var hwnd = NativeMethods.GetForegroundWindow();
        if (hwnd == nint.Zero)
        {
            throw new BridgeException("NO_FOREGROUND_WINDOW", "Windows has no foreground window.");
        }

        using var automation = new UIA3Automation();
        AutomationElement root;
        try
        {
            root = automation.FromHandle(hwnd);
        }
        catch (Exception ex)
        {
            throw new BridgeException("UIA_ROOT_FAILURE", "Unable to resolve the foreground window through UI Automation.", ex);
        }

        var snapshotId = Guid.NewGuid().ToString("N");
        var elements = new List<UiElementDto>(Math.Min(maxElements, 128));
        var walker = automation.TreeWalkerFactory.GetControlViewWalker();
        var truncated = false;
        var nextId = 0;

        AddElement(root, depth: 0, parentId: null);

        var processId = Safe(() => root.Properties.ProcessId.ValueOrDefault, 0);
        var processName = TryProcessName(processId);
        var foregroundTitle = Safe(() => root.Name, string.Empty);
        var rootBounds = Safe(() => root.BoundingRectangle, Rectangle.Empty);

        ScreenshotDto? screenshot = null;
        if (includeScreenshot)
        {
            screenshot = CaptureElement(root, screenshotMaxWidth);
        }

        return new SnapshotDto(
            SnapshotId: snapshotId,
            CapturedAt: DateTimeOffset.UtcNow,
            SessionId: health.SessionId,
            ForegroundProcessId: processId,
            ForegroundProcessName: NullIfEmpty(processName),
            ForegroundTitle: NullIfEmpty(foregroundTitle),
            ForegroundBounds: ToRect(rootBounds),
            Truncated: truncated,
            Elements: elements,
            Screenshot: screenshot);

        void AddElement(AutomationElement element, int depth, string? parentId)
        {
            if (elements.Count >= maxElements)
            {
                truncated = true;
                return;
            }

            var id = $"e{nextId++}";
            elements.Add(ToElementDto(element, id, depth, parentId));

            if (depth >= maxDepth)
            {
                return;
            }

            AutomationElement? child;
            try
            {
                child = walker.GetFirstChild(element);
            }
            catch
            {
                return;
            }

            while (child is not null)
            {
                AddElement(child, depth + 1, id);
                if (elements.Count >= maxElements)
                {
                    truncated = true;
                    return;
                }

                try
                {
                    child = walker.GetNextSibling(child);
                }
                catch
                {
                    return;
                }
            }
        }
    }

    private static UiElementDto ToElementDto(
        AutomationElement element,
        string id,
        int depth,
        string? parentId)
    {
        var bounds = Safe(() => element.BoundingRectangle, Rectangle.Empty);
        var patterns = Safe(
            () => element.FrameworkAutomationElement
                .GetSupportedPatterns()
                .Select(pattern => pattern.ToString())
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            Array.Empty<string>());

        return new UiElementDto(
            Id: id,
            Name: NullIfEmpty(Safe(() => element.Name, string.Empty)),
            AutomationId: NullIfEmpty(Safe(() => element.AutomationId, string.Empty)),
            ControlType: Safe(() => element.ControlType.ToString(), "Unknown"),
            ClassName: NullIfEmpty(Safe(() => element.ClassName, string.Empty)),
            Enabled: Safe(() => element.Properties.IsEnabled.ValueOrDefault, false),
            Offscreen: Safe(() => element.Properties.IsOffscreen.ValueOrDefault, true),
            KeyboardFocusable: Safe(() => element.Properties.IsKeyboardFocusable.ValueOrDefault, false),
            HasKeyboardFocus: Safe(() => element.Properties.HasKeyboardFocus.ValueOrDefault, false),
            Bounds: ToRect(bounds),
            Patterns: patterns,
            Depth: depth,
            ParentId: parentId);
    }

    private static ScreenshotDto CaptureElement(AutomationElement element, int maxWidth)
    {
        try
        {
            using var original = element.Capture();
            if (original.Width <= 0 || original.Height <= 0)
            {
                throw new BridgeException("SCREENSHOT_FAILURE", "The foreground window has an empty capture surface.");
            }

            using var scaled = ScaleDown(original, maxWidth);
            using var stream = new MemoryStream();
            scaled.Save(stream, ImageFormat.Png);
            return new ScreenshotDto(
                MimeType: "image/png",
                Data: Convert.ToBase64String(stream.ToArray()),
                Width: scaled.Width,
                Height: scaled.Height);
        }
        catch (BridgeException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new BridgeException("SCREENSHOT_FAILURE", "Unable to capture the foreground window.", ex);
        }
    }

    private static Bitmap ScaleDown(Bitmap source, int maxWidth)
    {
        if (source.Width <= maxWidth)
        {
            return new Bitmap(source);
        }

        var ratio = (double)maxWidth / source.Width;
        var height = Math.Max(1, (int)Math.Round(source.Height * ratio));
        return new Bitmap(source, new Size(maxWidth, height));
    }

    private static string? TryProcessName(int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private static int Clamp(int value, int min, int max, string field)
    {
        if (value < min || value > max)
        {
            throw new BridgeException(
                "INVALID_REQUEST",
                $"{field} must be between {min} and {max}.");
        }

        return value;
    }

    private static T Safe<T>(Func<T> read, T fallback)
    {
        try
        {
            return read();
        }
        catch
        {
            return fallback;
        }
    }

    private static RectDto ToRect(Rectangle rectangle) =>
        new(rectangle.X, rectangle.Y, rectangle.Width, rectangle.Height);

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static partial class NativeMethods
    {
        [LibraryImport("user32.dll")]
        internal static partial nint GetForegroundWindow();
    }
}

internal sealed class BridgeException : Exception
{
    public BridgeException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    public string Code { get; }
}
