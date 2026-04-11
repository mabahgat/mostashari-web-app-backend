import { Request, Response, NextFunction } from 'express';
import { loadConfig } from '../config/loader';
import { UnauthorizedError } from './errors';

// Extend Express Request to carry the authenticated client name
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      clientName?: string;
    }
  }
}

function isLocalhost(req: Request): boolean {
  const ip = req.ip ?? req.socket.remoteAddress ?? '';
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

export function authenticate(req: Request, _res: Response, next: NextFunction): void {
  const { mode, auth } = loadConfig();

  // In dev mode, localhost requests are auto-authenticated — no key required
  if (mode === 'dev' && isLocalhost(req)) {
    req.clientName = 'dev-local';
    return next();
  }

  const apiKey = req.headers['x-api-key'];

  if (!apiKey || typeof apiKey !== 'string') {
    return next(new UnauthorizedError('Missing X-API-Key header'));
  }

  const match = auth.apiKeys.find((entry) => entry.key === apiKey);

  if (!match) {
    return next(new UnauthorizedError('Invalid API key'));
  }

  req.clientName = match.name;
  next();
}
