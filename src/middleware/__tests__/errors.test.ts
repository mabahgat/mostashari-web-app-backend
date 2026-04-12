import {
  AppError,
  UnauthorizedError,
  NotFoundError,
  SessionExpiredError,
  ValidationError,
  UpstreamError,
} from '../errors';

describe('middleware/errors', () => {
  describe('AppError', () => {
    it('should create error with status code, message, and code', () => {
      const error = new AppError(500, 'Something went wrong', 'INTERNAL');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(500);
      expect(error.message).toBe('Something went wrong');
      expect(error.code).toBe('INTERNAL');
      expect(error.name).toBe('AppError');
    });

    it('should allow code to be optional', () => {
      const error = new AppError(400, 'Bad request');

      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Bad request');
      expect(error.code).toBeUndefined();
    });

    it('should maintain prototype chain', () => {
      const error = new AppError(404, 'Not found');

      expect(Object.getPrototypeOf(error)).toBe(AppError.prototype);
    });

    it('should have stack trace', () => {
      const error = new AppError(500, 'Test error');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('AppError');
    });
  });

  describe('UnauthorizedError', () => {
    it('should create 401 error with default message', () => {
      const error = new UnauthorizedError();

      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Unauthorized');
      expect(error.code).toBe('UNAUTHORIZED');
    });

    it('should create 401 error with custom message', () => {
      const error = new UnauthorizedError('Invalid token');

      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Invalid token');
      expect(error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('NotFoundError', () => {
    it('should create 404 error with default message', () => {
      const error = new NotFoundError();

      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(404);
      expect(error.message).toBe('Resource not found');
      expect(error.code).toBe('NOT_FOUND');
    });

    it('should create 404 error with custom resource name', () => {
      const error = new NotFoundError('Session');

      expect(error.statusCode).toBe(404);
      expect(error.message).toBe('Session not found');
      expect(error.code).toBe('NOT_FOUND');
    });
  });

  describe('SessionExpiredError', () => {
    it('should create 410 error', () => {
      const error = new SessionExpiredError();

      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(410);
      expect(error.message).toBe('Session has expired');
      expect(error.code).toBe('SESSION_EXPIRED');
    });
  });

  describe('ValidationError', () => {
    it('should create 400 error with custom message', () => {
      const error = new ValidationError('Invalid email format');

      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Invalid email format');
      expect(error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('UpstreamError', () => {
    it('should create 502 error with custom message', () => {
      const error = new UpstreamError('Azure service unavailable');

      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(502);
      expect(error.message).toBe('Azure service unavailable');
      expect(error.code).toBe('UPSTREAM_ERROR');
    });
  });
});
