import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { generateResponse } from '../services/responsesService';
import { loadConfig } from '../config/loader';
import { ValidationError, AppError } from '../middleware/errors';

const router = Router();

const GenerateBodySchema = z.object({
  userInput: z.string().min(1, 'userInput must not be empty'),
});

router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  const { safeguards } = loadConfig();

  // Validate request body
  const parsed = GenerateBodySchema.safeParse(req.body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return next(new ValidationError(issue?.message ?? 'Invalid request body'));
  }

  const { userInput } = parsed.data;

  // Enforce message character limit
  if (userInput.length > safeguards.maxMessageChars) {
    return next(
      new ValidationError(`userInput exceeds the ${safeguards.maxMessageChars}-character limit`)
    );
  }

  // Wrap Azure call with a configurable timeout
  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new AppError(504, `Azure OpenAI request timed out after ${safeguards.azureTimeoutMs / 1000}s. Try again.`, 'UPSTREAM_TIMEOUT')),
      safeguards.azureTimeoutMs
    )
  );

  try {
    const result = await Promise.race([generateResponse(userInput), timeoutPromise]);

    res.json({
      reply: result.reply,
      model: result.model,
      usage: result.usage,
    });
  } catch (err) {
    // Map upstream errors to UpstreamError for consistent error envelope
    if (err instanceof AppError) return next(err);
    const message = err instanceof Error ? err.message : String(err);
    return next(new AppError(502, `Azure OpenAI Responses error: ${message}`, 'UPSTREAM_ERROR'));
  }
});

export default router;
