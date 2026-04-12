import request from 'supertest';
import express, { Application } from 'express';
import sessionsRouter from '../../routes/sessions';
import { authenticate } from '../../middleware/auth';
import { errorHandler } from '../../middleware/errorHandler';
import {
  createSession,
  getSession,
  deleteSession,
  listSessions,
} from '../../services/sessionService';
import { createThread, deleteThread } from '../../services/azureService';
import { loadConfig } from '../../config/loader';

jest.mock('../../services/sessionService');
jest.mock('../../services/azureService');
jest.mock('../../config/loader');

const mockCreateSession = createSession as jest.MockedFunction<typeof createSession>;
const mockGetSession = getSession as jest.MockedFunction<typeof getSession>;
const mockDeleteSession = deleteSession as jest.MockedFunction<typeof deleteSession>;
const mockListSessions = listSessions as jest.MockedFunction<typeof listSessions>;
const mockCreateThread = createThread as jest.MockedFunction<typeof createThread>;
const mockDeleteThread = deleteThread as jest.MockedFunction<typeof deleteThread>;
const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('routes/sessions', () => {
  let app: Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.clientName = 'test-client';
      next();
    });
    app.use('/sessions', sessionsRouter);
    app.use(errorHandler);

    mockLoadConfig.mockReturnValue({
      mode: 'dev',
      safeguards: {
        maxTotalSessions: 200,
        maxSessionsPerClient: 10,
      },
    } as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /sessions', () => {
    it('should create a new session', async () => {
      mockListSessions.mockResolvedValue([]);
      mockCreateThread.mockResolvedValue('thread-123');
      mockCreateSession.mockResolvedValue({
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 0,
        history: [],
      });

      const response = await request(app)
        .post('/sessions')
        .send();

      expect(response.status).toBe(201);
      expect(response.body).toEqual({
        sessionId: 'session-123',
        clientName: 'test-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
      });
      expect(mockCreateThread).toHaveBeenCalled();
      expect(mockCreateSession).toHaveBeenCalledWith('test-client', 'thread-123');
    });

    it('should reject when max total sessions reached', async () => {
      const existingSessions = Array.from({ length: 200 }, (_, i) => ({
        id: `session-${i}`,
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
      }));

      mockListSessions.mockResolvedValue(existingSessions);

      const response = await request(app)
        .post('/sessions')
        .send();

      expect(response.status).toBe(429);
      expect(response.body.error.code).toBe('SESSION_LIMIT');
      expect(response.body.error.message).toContain('Server session limit reached');
    });

    it('should reject when client reaches max sessions', async () => {
      const clientSessions = Array.from({ length: 10 }, (_, i) => ({
        id: `session-${i}`,
        clientName: 'test-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
      }));

      mockListSessions.mockResolvedValue(clientSessions);

      const response = await request(app)
        .post('/sessions')
        .send();

      expect(response.status).toBe(429);
      expect(response.body.error.code).toBe('SESSION_LIMIT');
      expect(response.body.error.message).toContain('maximum of 10 concurrent sessions');
    });

    it('should allow session creation when other clients have sessions', async () => {
      const otherClientSessions = Array.from({ length: 5 }, (_, i) => ({
        id: `session-${i}`,
        clientName: 'other-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
      }));

      mockListSessions.mockResolvedValue(otherClientSessions);
      mockCreateThread.mockResolvedValue('thread-new');
      mockCreateSession.mockResolvedValue({
        id: 'session-new',
        clientName: 'test-client',
        threadId: 'thread-new',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 0,
        history: [],
      });

      const response = await request(app)
        .post('/sessions')
        .send();

      expect(response.status).toBe(201);
    });
  });

  describe('GET /sessions', () => {
    it('should list all sessions', async () => {
      const sessions = [
        {
          id: 'session-1',
          clientName: 'client1',
          createdAt: '2024-01-01T00:00:00.000Z',
          lastActivityAt: '2024-01-01T00:00:00.000Z',
          status: 'active' as const,
          messageCount: 5,
        },
        {
          id: 'session-2',
          clientName: 'client2',
          createdAt: '2024-01-01T01:00:00.000Z',
          lastActivityAt: '2024-01-01T02:00:00.000Z',
          status: 'active' as const,
          messageCount: 10,
        },
      ];

      mockListSessions.mockResolvedValue(sessions);

      const response = await request(app)
        .get('/sessions');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        sessions,
        total: 2,
      });
    });

    it('should return empty array when no sessions exist', async () => {
      mockListSessions.mockResolvedValue([]);

      const response = await request(app)
        .get('/sessions');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        sessions: [],
        total: 0,
      });
    });
  });

  describe('GET /sessions/:id', () => {
    it('should return session details with recent messages', async () => {
      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 2,
        history: [
          { role: 'user' as const, content: 'Hello', timestamp: '2024-01-01T00:00:00.000Z' },
          { role: 'assistant' as const, content: 'Hi', timestamp: '2024-01-01T00:00:01.000Z' },
        ],
      };

      mockGetSession.mockResolvedValue(session);

      const response = await request(app)
        .get('/sessions/session-123');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        id: 'session-123',
        clientName: 'test-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 2,
        recentMessages: session.history,
        historyLength: 2,
      });
      expect(response.body).not.toHaveProperty('threadId');
    });

    it('should return 404 for non-existent session', async () => {
      mockGetSession.mockResolvedValue(null);

      const response = await request(app)
        .get('/sessions/00000000-0000-0000-0000-000000000000');

      expect(response.status).toBe(404);
      expect(response.body.error.code).toBe('NOT_FOUND');
    });

    it('should return 400 for invalid UUID format', async () => {
      const response = await request(app)
        .get('/sessions/invalid-id');

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('Invalid session ID format');
    });

    it('should limit recent messages to last 10', async () => {
      const history = Array.from({ length: 20 }, (_, i) => ({
        role: (i % 2 === 0 ? 'user' : 'assistant') as 'user' | 'assistant',
        content: `Message ${i}`,
        timestamp: new Date().toISOString(),
      }));

      const session = {
        id: 'session-123',
        clientName: 'test-client',
        threadId: 'thread-123',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 20,
        history,
      };

      mockGetSession.mockResolvedValue(session);

      const response = await request(app)
        .get('/sessions/session-123');

      expect(response.status).toBe(200);
      expect(response.body.recentMessages).toHaveLength(10);
      expect(response.body.historyLength).toBe(20);
      expect(response.body.recentMessages[0].content).toBe('Message 10');
    });
  });

  describe('DELETE /sessions/:id', () => {
    it('should delete a session and its Azure thread', async () => {
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
      mockDeleteThread.mockResolvedValue(undefined);
      mockDeleteSession.mockResolvedValue(true);

      const response = await request(app)
        .delete('/sessions/session-123');

      expect(response.status).toBe(204);
      expect(mockDeleteThread).toHaveBeenCalledWith('thread-123');
      expect(mockDeleteSession).toHaveBeenCalledWith('session-123');
    });

    it('should return 404 when session does not exist (getSession)', async () => {
      mockGetSession.mockResolvedValue(null);

      const response = await request(app)
        .delete('/sessions/00000000-0000-0000-0000-000000000000');

      expect(response.status).toBe(404);
      expect(mockDeleteThread).not.toHaveBeenCalled();
    });

    it('should return 404 when session delete fails', async () => {
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
      mockDeleteThread.mockResolvedValue(undefined);
      mockDeleteSession.mockResolvedValue(false);

      const response = await request(app)
        .delete('/sessions/session-123');

      expect(response.status).toBe(404);
    });

    it('should return 400 for invalid UUID format', async () => {
      const response = await request(app)
        .delete('/sessions/invalid-id');

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should succeed even if Azure thread deletion fails', async () => {
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
      mockDeleteThread.mockRejectedValue(new Error('Azure error'));
      mockDeleteSession.mockResolvedValue(true);

      const response = await request(app)
        .delete('/sessions/session-123');

      expect(response.status).toBe(204);
      expect(mockDeleteSession).toHaveBeenCalled();
    });
  });
});
