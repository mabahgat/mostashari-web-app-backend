import { Request, Response, NextFunction } from 'express';
import { authenticate } from '../auth';
import { UnauthorizedError } from '../errors';
import { loadConfig, _resetConfig } from '../../config/loader';

jest.mock('../../config/loader');

const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('middleware/auth', () => {
  let mockReq: any;
  let mockRes: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    mockReq = {
      headers: {},
      ip: '192.168.1.1',
      socket: { remoteAddress: '192.168.1.1' },
    };
    mockRes = {};
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('dev mode with localhost', () => {
    beforeEach(() => {
      mockLoadConfig.mockReturnValue({
        mode: 'dev',
        auth: { apiKeys: [{ name: 'prod-key', key: 'secret' }] },
      } as any);
    });

    it('should auto-authenticate localhost requests (127.0.0.1)', () => {
      mockReq.ip = '127.0.0.1';

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('dev-local');
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockNext).not.toHaveBeenCalledWith(expect.any(Error));
    });

    it('should auto-authenticate localhost requests (::1)', () => {
      mockReq.ip = '::1';

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('dev-local');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should auto-authenticate localhost requests (::ffff:127.0.0.1)', () => {
      mockReq.ip = '::ffff:127.0.0.1';

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('dev-local');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should require API key for non-localhost in dev mode', () => {
      mockReq.ip = '192.168.1.10';

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
      expect(mockReq.clientName).toBeUndefined();
    });

    it('should use socket.remoteAddress if req.ip is undefined', () => {
      mockReq.ip = undefined;
      mockReq.socket = { remoteAddress: '127.0.0.1' };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('dev-local');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle missing IP gracefully', () => {
      mockReq.ip = undefined;
      mockReq.socket = { remoteAddress: undefined };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
    });
  });

  describe('prod mode', () => {
    beforeEach(() => {
      mockLoadConfig.mockReturnValue({
        mode: 'prod',
        auth: {
          apiKeys: [
            { name: 'client1', key: 'key-abc-123' },
            { name: 'client2', key: 'key-def-456' },
          ],
        },
      } as any);
    });

    it('should reject requests without X-API-Key header', () => {
      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
      const error = mockNext.mock.calls[0][0];
      expect(error.message).toContain('Missing X-API-Key');
    });

    it('should reject requests with invalid API key', () => {
      mockReq.headers = { 'x-api-key': 'invalid-key' };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
      const error = mockNext.mock.calls[0][0];
      expect(error.message).toContain('Invalid API key');
    });

    it('should accept valid API key and set clientName', () => {
      mockReq.headers = { 'x-api-key': 'key-abc-123' };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('client1');
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockNext).not.toHaveBeenCalledWith(expect.any(Error));
    });

    it('should handle multiple valid keys', () => {
      mockReq.headers = { 'x-api-key': 'key-def-456' };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('client2');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject when header is an array', () => {
      mockReq.headers = { 'x-api-key': ['key1', 'key2'] };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
    });

    it('should not auto-authenticate localhost in prod mode', () => {
      mockReq.ip = '127.0.0.1';

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
      expect(mockReq.clientName).toBeUndefined();
    });
  });

  describe('stage mode', () => {
    beforeEach(() => {
      mockLoadConfig.mockReturnValue({
        mode: 'stage',
        auth: { apiKeys: [{ name: 'stage-client', key: 'stage-key' }] },
      } as any);
    });

    it('should not auto-authenticate localhost in stage mode', () => {
      mockReq.ip = '127.0.0.1';

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(UnauthorizedError));
    });

    it('should require valid API key', () => {
      mockReq.headers = { 'x-api-key': 'stage-key' };

      authenticate(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.clientName).toBe('stage-client');
      expect(mockNext).toHaveBeenCalledWith();
    });
  });
});
