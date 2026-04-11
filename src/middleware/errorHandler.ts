import { Request, Response, NextFunction } from 'express';
import { AppError } from './errors';
import logger from '../services/logger';
import { loadConfig } from '../config/loader';

function isVerboseMode(): boolean {
  try {
    const { mode } = loadConfig();
    return mode === 'dev' || mode === 'stage';
  } catch {
    return true;
  }
}

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
): void {
  const verbose = isVerboseMode();

  // Handle Express body-parser errors (e.g. payload too large, malformed JSON)
  const expressErrType = (err as { type?: string }).type;
  if (expressErrType === 'entity.too.large') {
    logger.warn('Client error', { code: 'PAYLOAD_TOO_LARGE', message: err.message });
    res.status(413).json({
      error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds the allowed size limit.' },
    });
    return;
  }
  if (expressErrType === 'entity.parse.failed') {
    logger.warn('Client error', { code: 'INVALID_JSON', message: err.message });
    res.status(400).json({
      error: { code: 'INVALID_JSON', message: 'Request body contains invalid JSON.' },
    });
    return;
  }

  if (err instanceof AppError) {
    if (err.statusCode >= 500) {
      logger.error('Server error', { code: err.code, message: err.message, stack: err.stack });
    } else {
      logger.warn('Client error', { code: err.code, message: err.message });
    }

    res.status(err.statusCode).json({
      error: {
        code: err.code ?? 'ERROR',
        message: err.message,
        ...(verbose && err.statusCode >= 500 && err.stack ? { stack: err.stack } : {}),
      },
    });
    return;
  }

  logger.error('Unhandled error', { message: err.message, stack: err.stack });
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
      ...(verbose && err.stack ? { stack: err.stack } : {}),
    },
  });
}
