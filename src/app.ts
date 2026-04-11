import express, { Request, Response } from 'express';
import path from 'path';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import { authenticate } from './middleware/auth';
import { errorHandler } from './middleware/errorHandler';
import { createGlobalLimiter, createSessionCreateLimiter } from './middleware/rateLimiter';
import sessionsRouter from './routes/sessions';
import chatRouter from './routes/chat';
import generateRouter from './routes/generate';
import searchRouter from './routes/search';
import logger from './services/logger';
import spec from './openapi/spec';
import { loadConfig } from './config/loader';

const app = express();

const { safeguards, cors: corsConfig, mode } = loadConfig();

// CORS — must be before all other middleware so preflight OPTIONS is handled first.
// In dev mode, all localhost origins are always allowed.
// In other modes, only the origins listed in cors.allowedOrigins are permitted.
const isLocalhostOrigin = (origin: string) =>
  /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (server-to-server, curl, Swagger UI)
      if (!origin) return callback(null, true);

      if (mode === 'dev' && isLocalhostOrigin(origin)) return callback(null, true);

      const allowed = corsConfig.allowedOrigins;
      if (allowed.includes('*') || allowed.includes(origin)) return callback(null, true);

      callback(new Error(`CORS: origin '${origin}' is not allowed`));
    },
    credentials: corsConfig.allowCredentials,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-API-Key'],
  })
);
app.use(express.json({ limit: `${safeguards.requestBodyLimitKb}kb` }));

// Global rate limiter — applied to all API routes
const globalLimiter = createGlobalLimiter();
app.use('/sessions', globalLimiter);

// Request logging
app.use((req: Request, _res: Response, next) => {
  logger.info('Incoming request', { method: req.method, path: req.path });
  next();
});

// Swagger API explorer — no auth required
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(spec, { explorer: true }));

// Chat test UI (React SPA) — no auth required
const chatUiDist = path.join(__dirname, 'ui', 'dist');
app.use('/chat', express.static(chatUiDist));
app.get('/chat/*', (_req: Request, res: Response) => {
  res.sendFile(path.join(chatUiDist, 'index.html'));
});

// Health check (no auth required)
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Stricter rate limit for session creation
const sessionCreateLimiter = createSessionCreateLimiter();
app.post('/sessions', sessionCreateLimiter);

// All /sessions routes require authentication
app.use('/sessions', authenticate, sessionsRouter);
app.use('/sessions', authenticate, chatRouter);

// Single-turn generate endpoint — auth required, global rate limiter already applied above
app.use('/generate', globalLimiter, authenticate, generateRouter);

// Search endpoint — auth required, global rate limiter applied
app.use('/search', globalLimiter, authenticate, searchRouter);

// 404 handler for unknown routes
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found' } });
});

// Global error handler (must be last)
app.use(errorHandler);

export default app;
