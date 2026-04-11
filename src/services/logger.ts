import winston from 'winston';
import { loadConfig } from '../config/loader';
import { AppMode } from '../config/types';

function buildLogger(mode: AppMode): winston.Logger {
  const isVerbose = mode === 'dev' || mode === 'stage';
  const level = isVerbose ? 'debug' : 'info';

  const prettyFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.colorize(),
    winston.format.printf(({ timestamp, level: lvl, message, ...meta }) => {
      const extras = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
      return `${timestamp} [${lvl}] ${message}${extras}`;
    })
  );

  const jsonFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  );

  return winston.createLogger({
    level,
    format: mode === 'prod' ? jsonFormat : prettyFormat,
    transports: [new winston.transports.Console()],
  });
}

let loggerInstance: winston.Logger | null = null;

function getLogger(): winston.Logger {
  if (!loggerInstance) {
    try {
      const { mode } = loadConfig();
      loggerInstance = buildLogger(mode);
    } catch {
      // Config not yet loaded — fall back to a basic debug logger
      loggerInstance = buildLogger('dev');
    }
  }
  return loggerInstance;
}

/** Proxy object so callers always get the current logger instance. */
const logger: winston.Logger = new Proxy({} as winston.Logger, {
  get(_target, prop) {
    return (getLogger() as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export default logger;

