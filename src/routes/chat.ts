import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { getSession, appendMessages } from '../services/sessionService';
import { sendMessage } from '../services/azureService';
import { NotFoundError, ValidationError, UpstreamError, AppError } from '../middleware/errors';
import { Message } from '../types';
import logger from '../services/logger';
import { loadConfig } from '../config/loader';

const router = Router();

// POST /sessions/:id/messages — send a chat message within a session
router.post('/:id/messages', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { safeguards } = loadConfig();

    const idSchema = z.string().uuid();
    const idParsed = idSchema.safeParse(req.params.id);
    if (!idParsed.success) {
      throw new ValidationError('Invalid session ID format');
    }

    // Validate message: not empty, within configured char limit
    const MessageBodySchema = z.object({
      message: z
        .string()
        .min(1, 'message must not be empty')
        .max(
          safeguards.maxMessageChars,
          `Message exceeds the ${safeguards.maxMessageChars}-character limit`
        ),
    });

    const bodyParsed = MessageBodySchema.safeParse(req.body);
    if (!bodyParsed.success) {
      const issue = bodyParsed.error.issues[0];
      throw new ValidationError(issue?.message ?? 'Invalid request body');
    }

    const session = await getSession(idParsed.data);
    if (!session) {
      throw new NotFoundError('Session');
    }

    const { message } = bodyParsed.data;
    const now = new Date().toISOString();

    let replyText: string;
    try {
      // Wrap the Azure call with a configurable timeout
      replyText = await Promise.race([
        sendMessage(session.threadId, message),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error(`Azure AI Foundry call timed out after ${safeguards.azureTimeoutMs / 1000}s`)),
            safeguards.azureTimeoutMs
          )
        ),
      ]);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : 'Unknown Azure error';
      const isTimeout = errMsg.includes('timed out');
      logger.error('Azure AI Foundry call failed', {
        sessionId: session.id,
        error: errMsg,
        timeout: isTimeout,
      });
      if (isTimeout) {
        throw new AppError(504, `Azure AI Foundry request timed out after ${safeguards.azureTimeoutMs / 1000}s. Try again.`, 'UPSTREAM_TIMEOUT');
      }
      throw new UpstreamError(`Azure AI Foundry error: ${errMsg}`);
    }

    const userMessage: Message = { role: 'user', content: message, timestamp: now };
    const assistantMessage: Message = {
      role: 'assistant',
      content: replyText,
      timestamp: new Date().toISOString(),
    };

    const updated = await appendMessages(session, userMessage, assistantMessage);

    res.json({
      sessionId: updated.id,
      reply: replyText,
      messageCount: updated.messageCount,
      lastActivityAt: updated.lastActivityAt,
    });
  } catch (err) {
    next(err);
  }
});

export default router;

