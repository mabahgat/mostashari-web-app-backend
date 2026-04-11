import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import {
  createSession,
  getSession,
  deleteSession,
  listSessions,
} from '../services/sessionService';
import { createThread, deleteThread } from '../services/azureService';
import { NotFoundError, ValidationError, AppError } from '../middleware/errors';
import { loadConfig } from '../config/loader';

const router = Router();

// POST /sessions — create a new session (creates Azure thread)
router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const clientName = req.clientName!;
    const { safeguards } = loadConfig();

    // Enforce total session cap and per-client cap
    const allSessions = await listSessions();

    if (allSessions.length >= safeguards.maxTotalSessions) {
      throw new AppError(
        429,
        `Server session limit reached (${safeguards.maxTotalSessions}). ` +
        `Delete an existing session before creating a new one.`,
        'SESSION_LIMIT'
      );
    }

    const clientSessions = allSessions.filter((s) => s.clientName === clientName);
    if (clientSessions.length >= safeguards.maxSessionsPerClient) {
      throw new AppError(
        429,
        `You have reached the maximum of ${safeguards.maxSessionsPerClient} concurrent sessions. ` +
        `Delete an existing session before creating a new one.`,
        'SESSION_LIMIT'
      );
    }

    // Allocate an Azure AI Foundry thread for this session
    const threadId = await createThread();

    const session = await createSession(clientName, threadId);

    res.status(201).json({
      sessionId: session.id,
      clientName: session.clientName,
      createdAt: session.createdAt,
      status: session.status,
    });
  } catch (err) {
    next(err);
  }
});

// GET /sessions — list all sessions
router.get('/', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const sessions = await listSessions();
    res.json({ sessions, total: sessions.length });
  } catch (err) {
    next(err);
  }
});

// GET /sessions/:id — get session details
router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const idSchema = z.string().uuid();
    const parsed = idSchema.safeParse(req.params.id);
    if (!parsed.success) {
      throw new ValidationError('Invalid session ID format');
    }

    const session = await getSession(parsed.data);
    if (!session) {
      throw new NotFoundError('Session');
    }

    // Return full session including trimmed history preview (last 10 messages)
    // threadId is intentionally excluded — it's an internal Azure reference
    const { history, threadId: _threadId, ...summary } = session;
    res.json({
      ...summary,
      recentMessages: history.slice(-10),
      historyLength: history.length,
    });
  } catch (err) {
    next(err);
  }
});

// DELETE /sessions/:id — terminate session (deletes Azure thread too)
router.delete('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const idSchema = z.string().uuid();
    const parsed = idSchema.safeParse(req.params.id);
    if (!parsed.success) {
      throw new ValidationError('Invalid session ID format');
    }

    const session = await getSession(parsed.data);
    if (!session) {
      throw new NotFoundError('Session');
    }

    // Delete the Azure thread first (best-effort — won't fail the request)
    await deleteThread(session.threadId);

    const deleted = await deleteSession(parsed.data);
    if (!deleted) {
      throw new NotFoundError('Session');
    }

    res.status(204).send();
  } catch (err) {
    next(err);
  }
});

export default router;

