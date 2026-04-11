import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { search, SearchMode } from '../services/searchService';
import { synthesizeSearchResults } from '../services/responsesService';
import { loadConfig } from '../config/loader';
import { ValidationError, AppError } from '../middleware/errors';
import logger from '../services/logger';

const router = Router();

const SearchBodySchema = z.object({
  query: z.string().min(1, 'query must not be empty'),
  mode: z.enum(['regulations', 'cases'], {
    errorMap: () => ({ message: 'mode must be "regulations" or "cases"' }),
  }),
  top: z.number().int().min(1).max(50).default(10),
  skip: z.number().int().min(0).default(0),
});

router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  const { safeguards } = loadConfig();

  const parsed = SearchBodySchema.safeParse(req.body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return next(new ValidationError(issue?.message ?? 'Invalid request body'));
  }

  const { query, mode, top, skip } = parsed.data;

  if (query.length > safeguards.maxMessageChars) {
    return next(
      new ValidationError(`query exceeds the ${safeguards.maxMessageChars}-character limit`)
    );
  }

  function makeTimeout(label: string): Promise<never> {
    return new Promise<never>((_, reject) =>
      setTimeout(
        () =>
          reject(
            new AppError(
              504,
              `${label} request timed out after ${safeguards.azureTimeoutMs / 1000}s. Try again.`,
              'UPSTREAM_TIMEOUT'
            )
          ),
        safeguards.azureTimeoutMs
      )
    );
  }

  // Step 1 — Azure AI Search
  let searchResult: Awaited<ReturnType<typeof search>>;
  try {
    searchResult = await Promise.race([
      search({ query, mode: mode as SearchMode, top, skip }),
      makeTimeout('Azure AI Search'),
    ]);
  } catch (err) {
    if (err instanceof AppError) return next(err);
    const message = err instanceof Error ? err.message : String(err);
    if (message.startsWith('Search mode') && message.includes('not configured')) {
      return next(new AppError(503, message, 'SEARCH_NOT_CONFIGURED'));
    }
    return next(new AppError(502, `Azure AI Search error: ${message}`, 'UPSTREAM_ERROR'));
  }

  // Step 2 — Foundry synthesis (graceful degradation: search results are always returned)
  let reply: string | null = null;
  let model: string | null = null;
  let usage: { inputTokens: number; outputTokens: number; totalTokens: number } | null = null;
  let synthesisError: string | undefined;

  try {
    const synthesis = await Promise.race([
      synthesizeSearchResults(query, mode, searchResult.results),
      makeTimeout('Azure AI Foundry synthesis'),
    ]);
    reply = synthesis.reply;
    model = synthesis.model;
    usage = synthesis.usage;
  } catch (synthErr) {
    const msg = synthErr instanceof Error ? synthErr.message : String(synthErr);
    logger.warn('Search synthesis failed — returning raw results only', { mode, query, error: msg });
    synthesisError = msg;
  }

  res.json({
    mode: searchResult.mode,
    query: searchResult.query,
    count: searchResult.count,
    top,
    skip,
    results: searchResult.results,
    reply,
    model,
    usage,
    ...(synthesisError !== undefined ? { synthesisError } : {}),
  });
});

export default router;
