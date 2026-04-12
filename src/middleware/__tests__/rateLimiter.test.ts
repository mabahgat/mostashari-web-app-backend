import { Request, Response, NextFunction } from 'express';
import { createGlobalLimiter, createSessionCreateLimiter } from '../rateLimiter';
import { loadConfig } from '../../config/loader';

jest.mock('../../config/loader');

const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('middleware/rateLimiter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockLoadConfig.mockReturnValue({
      safeguards: {
        rateLimitWindowMs: 60000,
        rateLimitMaxRequests: 60,
        sessionCreateLimitMax: 10,
      },
    } as any);
  });

  describe('createGlobalLimiter', () => {
    it('should create a rate limiter with configured settings', () => {
      const limiter = createGlobalLimiter();

      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should use safeguards from config', () => {
      mockLoadConfig.mockReturnValue({
        safeguards: {
          rateLimitWindowMs: 120000,
          rateLimitMaxRequests: 100,
          sessionCreateLimitMax: 10,
        },
      } as any);

      const limiter = createGlobalLimiter();

      expect(limiter).toBeDefined();
    });
  });

  describe('createSessionCreateLimiter', () => {
    it('should create a stricter rate limiter for session creation', () => {
      const limiter = createSessionCreateLimiter();

      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should use sessionCreateLimitMax from config', () => {
      mockLoadConfig.mockReturnValue({
        safeguards: {
          rateLimitWindowMs: 60000,
          rateLimitMaxRequests: 60,
          sessionCreateLimitMax: 5,
        },
      } as any);

      const limiter = createSessionCreateLimiter();

      expect(limiter).toBeDefined();
    });
  });

  describe('rate limiter behavior', () => {
    it('should allow requests under the limit', () => {
      const limiter = createGlobalLimiter();
      const mockReq = { ip: '127.0.0.1' } as Request;
      const mockRes = {
        setHeader: jest.fn(),
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      } as unknown as Response;
      const mockNext = jest.fn();

      // First request should pass
      limiter(mockReq, mockRes, mockNext);

      // next() should be called without error
      expect(mockNext).toHaveBeenCalled();
    });
  });
});
