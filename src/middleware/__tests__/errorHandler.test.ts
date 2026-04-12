import { Request, Response, NextFunction } from 'express';
import { errorHandler } from '../errorHandler';
import { AppError, UnauthorizedError, NotFoundError } from '../errors';
import { loadConfig } from '../../config/loader';
import logger from '../../services/logger';

jest.mock('../../config/loader');
jest.mock('../../services/logger', () => ({
  __esModule: true,
  default: {
    info: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('middleware/errorHandler', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  beforeEach(() => {
    mockReq = {};
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
    mockRes = {
      status: statusMock,
      json: jsonMock,
    };
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('AppError handling', () => {
    it('should handle 4xx client errors without stack trace', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new UnauthorizedError('Invalid credentials');

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid credentials',
        },
      });
      expect(logger.warn).toHaveBeenCalledWith(
        'Client error',
        expect.objectContaining({ code: 'UNAUTHORIZED' })
      );
    });

    it('should handle 404 errors', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new NotFoundError('Session');

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(statusMock).toHaveBeenCalledWith(404);
      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'NOT_FOUND',
          message: 'Session not found',
        },
      });
    });

    it('should log 5xx errors as server errors', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new AppError(500, 'Database connection failed', 'DB_ERROR');

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(logger.error).toHaveBeenCalledWith(
        'Server error',
        expect.objectContaining({
          code: 'DB_ERROR',
          message: 'Database connection failed',
        })
      );
      expect(statusMock).toHaveBeenCalledWith(500);
    });

    it('should include stack trace in dev mode for 5xx errors', () => {
      mockLoadConfig.mockReturnValue({ mode: 'dev' } as any);
      const error = new AppError(500, 'Internal error');
      error.stack = 'Error stack trace...';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(jsonMock).toHaveBeenCalledWith({
        error: expect.objectContaining({
          stack: 'Error stack trace...',
        }),
      });
    });

    it('should include stack trace in stage mode for 5xx errors', () => {
      mockLoadConfig.mockReturnValue({ mode: 'stage' } as any);
      const error = new AppError(502, 'Upstream failed');
      error.stack = 'Stack trace';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(jsonMock).toHaveBeenCalledWith({
        error: expect.objectContaining({
          stack: 'Stack trace',
        }),
      });
    });

    it('should not include stack trace in prod mode', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new AppError(500, 'Error', 'CODE');
      error.stack = 'Stack trace';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'CODE',
          message: 'Error',
        },
      });
    });

    it('should use error code or fallback to ERROR', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const errorWithCode = new AppError(400, 'Bad request', 'CUSTOM_CODE');
      const errorWithoutCode = new AppError(400, 'Bad request');

      errorHandler(errorWithCode, mockReq as Request, mockRes as Response, mockNext);
      expect(jsonMock).toHaveBeenCalledWith({
        error: expect.objectContaining({ code: 'CUSTOM_CODE' }),
      });

      errorHandler(errorWithoutCode, mockReq as Request, mockRes as Response, mockNext);
      expect(jsonMock).toHaveBeenCalledWith({
        error: expect.objectContaining({ code: 'ERROR' }),
      });
    });
  });

  describe('Express body-parser errors', () => {
    it('should handle entity.too.large error', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new Error('Payload too large') as any;
      error.type = 'entity.too.large';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(statusMock).toHaveBeenCalledWith(413);
      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'Request body exceeds the allowed size limit.',
        },
      });
      expect(logger.warn).toHaveBeenCalled();
    });

    it('should handle entity.parse.failed error', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new Error('Malformed JSON') as any;
      error.type = 'entity.parse.failed';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'INVALID_JSON',
          message: 'Request body contains invalid JSON.',
        },
      });
    });
  });

  describe('Unhandled errors', () => {
    it('should handle generic Error instances', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new Error('Something unexpected happened');

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected error occurred',
        },
      });
      expect(logger.error).toHaveBeenCalledWith(
        'Unhandled error',
        expect.objectContaining({ message: 'Something unexpected happened' })
      );
    });

    it('should include stack trace for unhandled errors in dev mode', () => {
      mockLoadConfig.mockReturnValue({ mode: 'dev' } as any);
      const error = new Error('Unexpected');
      error.stack = 'Full stack trace';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(jsonMock).toHaveBeenCalledWith({
        error: expect.objectContaining({
          stack: 'Full stack trace',
        }),
      });
    });

    it('should not include stack for unhandled errors in prod', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const error = new Error('Unexpected');
      error.stack = 'Stack';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(jsonMock).toHaveBeenCalledWith({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    });
  });

  describe('config loading failure handling', () => {
    it('should default to verbose mode when config loading fails', () => {
      mockLoadConfig.mockImplementation(() => {
        throw new Error('Config not loaded');
      });

      const error = new AppError(500, 'Test error');
      error.stack = 'Stack trace';

      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      // When config fails, it should default to verbose (include stack)
      expect(jsonMock).toHaveBeenCalledWith({
        error: expect.objectContaining({
          stack: 'Stack trace',
        }),
      });
    });
  });
});
