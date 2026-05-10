import { Router, Request, Response, NextFunction } from 'express';
import { getAgentInfo } from '../services/azureService';
import { AppError } from '../middleware/errors';

const router = Router();

router.get('/', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const info = await getAgentInfo();
    res.json(info);
  } catch (err) {
    if (err instanceof AppError) return next(err);
    const message = err instanceof Error ? err.message : String(err);
    return next(new AppError(502, `Failed to retrieve model info: ${message}`, 'UPSTREAM_ERROR'));
  }
});

export default router;
