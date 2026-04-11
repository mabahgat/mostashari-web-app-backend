import rateLimit from 'express-rate-limit';
import { loadConfig } from '../config/loader';
import { AppError } from './errors';

/**
 * Global rate limiter — applied to every API route.
 * Defaults: 60 requests per minute per IP.
 */
export function createGlobalLimiter() {
  const { safeguards } = loadConfig();
  return rateLimit({
    windowMs: safeguards.rateLimitWindowMs,
    max: safeguards.rateLimitMaxRequests,
    standardHeaders: true,   // Return X-RateLimit-* headers
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    handler: (_req, _res, next) => next(
      new AppError(
        429,
        `Too many requests. Limit is ${safeguards.rateLimitMaxRequests} per ${safeguards.rateLimitWindowMs / 1000}s window.`,
        'RATE_LIMIT'
      )
    ),
  });
}

/**
 * Stricter limiter for session creation (POST /sessions).
 * Defaults: 10 new sessions per minute per IP.
 */
export function createSessionCreateLimiter() {
  const { safeguards } = loadConfig();
  return rateLimit({
    windowMs: safeguards.rateLimitWindowMs,
    max: safeguards.sessionCreateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, _res, next) => next(
      new AppError(
        429,
        `Too many sessions created. Limit is ${safeguards.sessionCreateLimitMax} per ${safeguards.rateLimitWindowMs / 1000}s window.`,
        'RATE_LIMIT'
      )
    ),
  });
}
