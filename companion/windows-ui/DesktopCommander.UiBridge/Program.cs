using DesktopCommander.UiBridge;

using var shutdown = new CancellationTokenSource();

Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

AppDomain.CurrentDomain.ProcessExit += (_, _) => shutdown.Cancel();

var server = new NamedPipeBridgeServer();

try
{
    await server.RunAsync(shutdown.Token);
}
catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
{
}
