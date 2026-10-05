using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace DesktopCommander.UiBridge;

internal sealed class NamedPipeBridgeServer
{
    public const string PipeName = "DesktopCommander.UiBridge.v1";
    private const int MaxRequestBytes = 64 * 1024;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);

    private readonly UiSnapshotService _snapshotService = new();
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var pipe = new NamedPipeServerStream(
                PipeName,
                PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

            await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            await HandleConnectionAsync(pipe, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleConnectionAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);

        using var reader = new StreamReader(
            pipe,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096,
            leaveOpen: true);
        await using var writer = new StreamWriter(
            pipe,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            bufferSize: 4096,
            leaveOpen: true)
        {
            AutoFlush = true,
            NewLine = "\n",
        };

        BridgeEnvelope response;
        try
        {
            var line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            if (line is null)
            {
                return;
            }

            if (Encoding.UTF8.GetByteCount(line) > MaxRequestBytes)
            {
                response = BridgeEnvelope.Failure("REQUEST_TOO_LARGE", "The UI bridge request exceeds the allowed size.");
            }
            else
            {
                response = Dispatch(line);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            response = BridgeEnvelope.Failure("REQUEST_TIMEOUT", "The UI bridge request timed out.");
        }
        catch (JsonException)
        {
            response = BridgeEnvelope.Failure("INVALID_JSON", "The UI bridge request is not valid JSON.");
        }
        catch (BridgeException ex)
        {
            response = BridgeEnvelope.Failure(ex.Code, ex.Message);
        }
        catch
        {
            response = BridgeEnvelope.Failure("INTERNAL_ERROR", "The UI bridge request failed.");
        }

        var json = JsonSerializer.Serialize(response, _json);
        await writer.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
    }

    private BridgeEnvelope Dispatch(string json)
    {
        var request = JsonSerializer.Deserialize<BridgeRequest>(json, _json)
            ?? throw new BridgeException("INVALID_REQUEST", "The UI bridge request body is empty.");

        return request.Method switch
        {
            "health" => BridgeEnvelope.Success(_snapshotService.GetHealth()),
            "snapshot" => BridgeEnvelope.Success(_snapshotService.Capture(request)),
            _ => BridgeEnvelope.Failure("UNKNOWN_METHOD", "The requested UI bridge method is not supported."),
        };
    }
}
