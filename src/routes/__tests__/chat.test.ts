import request from 'supertest';
import express, { Application } from 'express';
import chatRouter from '../../routes/chat';
import { errorHandler } from '../../middleware/errorHandler';
import { getSession, appendMessages } from '../../services/sessionService';
import { sendMessage } from '../../services/azureService';
import { loadConfig } from '../../config/loader';

jest.mock('../../services/sessionService');
jest.mock('../../services/azureService');
jest.mock('../../config/loader');

const mockGetSession = getSession as jest.MockedFunction<typeof getSession>;
const mockAppendMessages = appendMessages as jest.MockedFunction<typeof appendMessages>;
const mockSendMessage = sendMessage as jest.MockedFunction<typeof sendMessage>;
const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('routes/chat', () => {
  let app: Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.clientName = 'test-client';
      next();
    });
    app.use('/sessions', chatRouter);
    app.use(errorHandler);

    mockLoadConfig.mockReturnValue({
      mode: 'dev',
      safeguards: {
        maxMessageChars: 4000,
        azureTimeoutMs: 30000,
      },
    } as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /sessions/:id/messages', () => {
    it('should send a message and receive a reply', async () => {
      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      mockGetSession.mockResolvedValue(session);
      mockSendMessage.mockResolvedValue('This is the AI response');
      mockAppendMessages.mockResolvedValue({
        ...session,
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
        history: [
          { role: 'user', content: 'Hello', timestamp: expect.any(String) },
          { role: 'assistant', content: 'This is the AI response', timestamp: expect.any(String) },
        ],
      });

      const response = await request(app)
        .post('/sessions/session-123/messages')
        .send({ message: 'Hello' });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        sessionId: 'session-123',
        reply: 'This is the AI response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });
      expect(mockSendMessage).toHaveBeenCalledWith('thread-123', 'Hello');
    });

    it('should return 400 for invalid session ID format', async () => {
      const response = await request(app)
        .post('/sessions/invalid-id/messages')
        .send({ message: 'Test' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('Invalid session ID format');
    });

    it('should return 400 for empty message', async () => {
      const response = await request(app)
        .post('/sessions/00000000-0000-0000-0000-000000000000/messages')
        .send({ message: '' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('must not be empty');
    });

    it('should return 400 for missing message field', async () => {
      const response = await request(app)
        .post('/sessions/00000000-0000-0000-0000-000000000000/messages')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when message exceeds character limit', async () => {
      const longMessage = 'a'.repeat(4001);

      const response = await request(app)
        .post('/sessions/00000000-0000-0000-0000-000000000000/messages')
        .send({ message: longMessage });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('4000-character limit');
    });

    it('should return 404 when session does not exist', async () => {
      mockGetSession.mockResolvedValue(null);

      const response = await request(app)
        .post('/sessions/00000000-0000-0000-0000-000000000000/messages')
        .send({ message: 'Hello' });

      expect(response.status).toBe(404);
      expect(response.body.error.code).toBe('NOT_FOUND');
    });

    it('should handle Azure timeout gracefully', async () => {
      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      mockGetSession.mockResolvedValue(session);
      mockSendMessage.mockImplementation(
        () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error('timeout')), 100))
      );

      const response = await request(app)
        .post('/sessions/session-123/messages')
        .send({ message: 'Hello' });

      expect(response.status).toBe(504);
      expect(response.body.error.code).toBe('UPSTREAM_TIMEOUT');
      expect(response.body.error.message).toContain('timed out');
    }, 15000);

    it('should handle Azure errors gracefully', async () => {
      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      mockGetSession.mockResolvedValue(session);
      mockSendMessage.mockRejectedValue(new Error('Azure service unavailable'));

      const response = await request(app)
        .post('/sessions/session-123/messages')
        .send({ message: 'Hello' });

      expect(response.status).toBe(502);
      expect(response.body.error.code).toBe('UPSTREAM_ERROR');
      expect(response.body.error.message).toContain('Azure AI Foundry error');
    });

    it('should accept messages at character limit', async () => {
      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      const exactLimitMessage = 'a'.repeat(4000);

      mockGetSession.mockResolvedValue(session);
      mockSendMessage.mockResolvedValue('Response');
      mockAppendMessages.mockResolvedValue({
        ...session,
        messageCount: 2,
        history: [],
      });

      const response = await request(app)
        .post('/sessions/session-123/messages')
        .send({ message: exactLimitMessage });

      expect(response.status).toBe(200);
    });

    it('should handle non-Error Azure rejections', async () => {
      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      mockGetSession.mockResolvedValue(session);
      mockSendMessage.mockRejectedValue('String error');

      const response = await request(app)
        .post('/sessions/session-123/messages')
        .send({ message: 'Hello' });

      expect(response.status).toBe(502);
      expect(response.body.error.message).toContain('Unknown Azure error');
    });
  });
});
