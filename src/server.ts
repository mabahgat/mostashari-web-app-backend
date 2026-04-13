import { loadConfig } from './config/loader';
import { connectRedis } from './services/redisService';
import { initAgent } from './services/azureService';
import logger from './services/logger';
import app from './app';

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (err: unknown) {
    logger.error('Failed to load configuration', {
      message: err instanceof Error ? err.message : String(err),
    });
    process.exit(1);
  }

  logger.info(`Starting in [${config.mode}] mode`);

  if (config.mode === 'stage' || config.mode === 'prod') {
    try {
      await connectRedis();
    } catch (err: unknown) {
      logger.error('Failed to connect to Redis', {
        message: err instanceof Error ? err.message : String(err),
      });
      process.exit(1);
    }
  } else {
    logger.debug('dev mode: using in-memory session store (Redis not required)');
  }

  const { port, host } = config.server;

  // Start HTTP server immediately so Azure health checks and /sessions pass.
  // Agent initialisation runs in the background; routes that require it return 503
  // until it completes (via isAgentReady()).
  app.listen(port, host, () => {
    logger.info(`Chat backend listening on http://${host}:${port}`);
  });

  // Init agent non-blocking — failure is logged but does not crash the server.
  initAgent().catch((err: unknown) => {
    logger.error('Failed to initialise Azure OpenAI assistant (will retry on next request)', {
      message: err instanceof Error ? err.message : String(err),
    });
  });

  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`Received ${signal}, shutting down gracefully...`);
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err: unknown) => {
  console.error('Fatal error during startup:', err);
  process.exit(1);
});

