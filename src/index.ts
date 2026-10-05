#!/usr/bin/env node

// MUST be first: raises the libuv threadpool size before any fs work is
// submitted. See src/bootstrap.ts for why import order matters.
import './bootstrap.js';

type RuntimeLogger = {
  error(message: string): void;
  debug(message: string): void;
};

type RuntimeCapture = (
  event: string,
  data?: Record<string, unknown>,
) => unknown;

let runtimeLogger: RuntimeLogger | undefined;
let runtimeCapture: RuntimeCapture | undefined;

// Store messages to defer until after initialization
const deferredMessages: Array<{ level: string, message: string }> = [];
function deferLog(level: string, message: string) {
  deferredMessages.push({ level, message });
}

async function runServer() {
  try {
    // Maintenance commands intentionally load only their own runtime
    // dependencies. This keeps lifecycle recovery independent from the full
    // MCP server, PDF stack, browser tooling, and configuration bootstrap.
    if (process.argv[2] === 'setup') {
      const { runSetup } = await import('./npm-scripts/setup.js');
      await runSetup();
      return;
    }

    if (process.argv[2] === 'remove') {
      const { runUninstall } = await import('./npm-scripts/uninstall.js');
      await runUninstall();
      return;
    }

    if (process.argv[2] === 'remote') {
      const { runRemote } = await import('./npm-scripts/remote.js');
      await runRemote();
      return;
    }

    if (process.argv[2] === 'tunnel') {
      const { runTunnel } = await import('./npm-scripts/tunnel.js');
      await runTunnel(process.argv.slice(3));
      return;
    }

    if (process.argv[2] === 'ui-bridge') {
      const { runUiBridge } = await import('./npm-scripts/ui-bridge.js');
      await runUiBridge(process.argv.slice(3));
      return;
    }

    const [
      { FilteredStdioServerTransport },
      { server, flushDeferredMessages },
      { configManager },
      { featureFlagManager },
      captureModule,
      loggerModule,
      { ensureChromeAvailable },
    ] = await Promise.all([
      import('./custom-stdio.js'),
      import('./server.js'),
      import('./config-manager.js'),
      import('./utils/feature-flags.js'),
      import('./utils/capture.js'),
      import('./utils/logger.js'),
      import('./tools/pdf/markdown.js'),
    ]);
    await import('./command-manager.js');

    runtimeCapture = captureModule.capture;
    runtimeLogger = loggerModule.logger;
    const { capture } = captureModule;
    const { logToStderr, logger } = loggerModule;

    // Parse command line arguments for onboarding control
    const DISABLE_ONBOARDING = process.argv.includes('--no-onboarding');
    if (DISABLE_ONBOARDING) {
      logToStderr('info', 'Onboarding disabled via --no-onboarding flag');
    }

    // Set global flag for onboarding control
    (global as any).disableOnboarding = DISABLE_ONBOARDING;

    // Create transport FIRST so all logging gets properly buffered
    // This must happen before any code that might use logger.*
    const transport = new FilteredStdioServerTransport();

    // Export transport for use throughout the application
    global.mcpTransport = transport;

    try {
      deferLog('info', 'Loading configuration...');
      await configManager.loadConfig();
      deferLog('info', 'Configuration loaded successfully');

      // Initialize feature flags (non-blocking)
      deferLog('info', 'Initializing feature flags...');
      await featureFlagManager.initialize();
    } catch (configError) {
      deferLog('error', `Failed to load configuration: ${configError instanceof Error ? configError.message : String(configError)}`);
      if (configError instanceof Error && configError.stack) {
        deferLog('debug', `Stack trace: ${configError.stack}`);
      }
      deferLog('warning', 'Continuing with in-memory configuration only');
      // Continue anyway - we'll use an in-memory config
    }

    // Handle uncaught exceptions
    process.on('uncaughtException', async (error) => {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // If this is a JSON parsing error, log it to stderr but don't crash
      if (errorMessage.includes('JSON') && errorMessage.includes('Unexpected token')) {
        logger.error(`JSON parsing error: ${errorMessage}`);
        return; // Don't exit on JSON parsing errors
      }

      capture('run_server_uncaught_exception', {
        error: errorMessage
      });

      logger.error(`Uncaught exception: ${errorMessage}`);
      process.exit(1);
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', async (reason) => {
      const errorMessage = reason instanceof Error ? reason.message : String(reason);

      // If this is a JSON parsing error, log it to stderr but don't crash
      if (errorMessage.includes('JSON') && errorMessage.includes('Unexpected token')) {
        logger.error(`JSON parsing rejection: ${errorMessage}`);
        return; // Don't exit on JSON parsing errors
      }

      capture('run_server_unhandled_rejection', {
        error: errorMessage
      });

      logger.error(`Unhandled rejection: ${errorMessage}`);
      process.exit(1);
    });

    capture('run_server_start');

    deferLog('info', 'Connecting server...');

    // Set up event-driven initialization completion handler
    server.oninitialized = () => {
      // This callback is triggered after the client sends the "initialized" notification
      // At this point, the MCP protocol handshake is fully complete
      transport.enableNotifications();

      // Flush all deferred messages from both index.ts and server.ts
      while (deferredMessages.length > 0) {
        const msg = deferredMessages.shift()!;
        transport.sendLog('info', msg.message);
      }
      flushDeferredMessages();

      // Now we can send regular logging messages
      transport.sendLog('info', 'Server connected successfully');
      transport.sendLog('info', 'MCP fully initialized, all startup messages sent');

      // Preemptively check/download Chrome for PDF generation (runs in background)
      ensureChromeAvailable();
    };

    await server.connect(transport);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (runtimeLogger) {
      runtimeLogger.error(`FATAL ERROR: ${errorMessage}`);
      if (error instanceof Error && error.stack) {
        runtimeLogger.debug(error.stack);
      }
    } else {
      console.error(`FATAL ERROR: ${errorMessage}`);
      if (error instanceof Error && error.stack) {
        console.error(error.stack);
      }
    }

    // Send a structured error notification
    const errorNotification = {
      jsonrpc: "2.0" as const,
      method: "notifications/message",
      params: {
        level: "error",
        logger: "desktop-commander",
        data: `Failed to start server: ${errorMessage} (${new Date().toISOString()})`
      }
    };
    process.stdout.write(JSON.stringify(errorNotification) + '\n');

    runtimeCapture?.('run_server_failed_start_error', {
      error: errorMessage
    });
    process.exit(1);
  }
}

runServer().catch(async (error) => {
  const errorMessage = error instanceof Error ? error.message : String(error);
  console.error(`RUNTIME ERROR: ${errorMessage}`);
  console.error(error instanceof Error && error.stack ? error.stack : 'No stack trace available');
  process.stderr.write(JSON.stringify({
    type: 'error',
    timestamp: new Date().toISOString(),
    message: `Fatal error running server: ${errorMessage}`
  }) + '\n');


  runtimeCapture?.('run_server_fatal_error', {
    error: errorMessage
  });
  process.exit(1);
});