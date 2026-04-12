import { RedisSessionStore } from '../../stores/RedisSessionStore';
import { loadConfig } from '../../../config/loader';
import { getRedisClient } from '../../redisService';
import logger from '../../logger';

jest.mock('../../../config/loader');
jest.mock('../../redisService');
jest.mock('../../logger', () => ({
  __esModule: true,
  default: {
    info: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;
const mockGetRedisClient = getRedisClient as jest.MockedFunction<typeof getRedisClient>;

describe('services/stores/RedisSessionStore', () => {
  let store: RedisSessionStore;
  let mockRedis: any;

  beforeEach(() => {
    jest.clearAllMocks();

    mockLoadConfig.mockReturnValue({
      session: {
        timeoutMinutes: 30,
        maxHistoryLength: 100,
      },
    } as any);

    mockRedis = {
      set: jest.fn().mockResolvedValue('OK'),
      get: jest.fn().mockResolvedValue(null),
      del: jest.fn().mockResolvedValue(0),
      scan: jest.fn().mockResolvedValue(['0', []]),
      pipeline: jest.fn().mockReturnValue({
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([]),
      }),
    };

    mockGetRedisClient.mockReturnValue(mockRedis);
    store = new RedisSessionStore();
  });

  describe('createSession', () => {
    it('should create a new session with generated ID', async () => {
      const session = await store.createSession('test-client', 'thread-123');

      expect(session.id).toBeDefined();
      expect(session.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(session.clientName).toBe('test-client');
      expect(session.threadId).toBe('thread-123');
      expect(session.status).toBe('active');
      expect(session.messageCount).toBe(0);
      expect(session.history).toEqual([]);
    });

    it('should store session in Redis with TTL', async () => {
      const session = await store.createSession('client', 'thread');

      expect(mockRedis.set).toHaveBeenCalledWith(
        `session:${session.id}`,
        expect.stringContaining(session.id),
        'EX',
        1800 // 30 minutes in seconds
      );
    });

    it('should log session creation', async () => {
      await store.createSession('client1', 'thread-abc');

      expect(logger.info).toHaveBeenCalledWith(
        'Session created',
        expect.objectContaining({ clientName: 'client1' })
      );
    });

    it('should use configured TTL', async () => {
      mockLoadConfig.mockReturnValue({
        session: { timeoutMinutes: 60, maxHistoryLength: 100 },
      } as any);

      const session = await store.createSession('client', 'thread');

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        'EX',
        3600 // 60 minutes
      );
    });
  });

  describe('getSession', () => {
    it('should retrieve an existing session from Redis', async () => {
      const sessionData = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 0,
        history: [],
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(sessionData));

      const session = await store.getSession('test-id');

      expect(mockRedis.get).toHaveBeenCalledWith('session:test-id');
      expect(session).toEqual(sessionData);
    });

    it('should return null for non-existent session', async () => {
      mockRedis.get.mockResolvedValue(null);

      const result = await store.getSession('non-existent');

      expect(result).toBeNull();
    });

    it('should parse JSON correctly', async () => {
      const sessionData = {
        id: 'id-123',
        clientName: 'test',
        threadId: 'thread-abc',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T01:00:00.000Z',
        status: 'active',
        messageCount: 5,
        history: [
          { role: 'user', content: 'Hello', timestamp: '2024-01-01T00:00:00.000Z' },
        ],
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(sessionData));

      const session = await store.getSession('id-123');

      expect(session?.history).toHaveLength(1);
      expect(session?.messageCount).toBe(5);
    });
  });

  describe('updateSession', () => {
    it('should update session lastActivityAt and save to Redis', async () => {
      const session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [] as any[],
      };

      const updated = await store.updateSession(session);

      expect(updated.lastActivityAt).not.toBe('2024-01-01T00:00:00.000Z');
      expect(mockRedis.set).toHaveBeenCalledWith(
        'session:test-id',
        expect.stringContaining('test-id'),
        'EX',
        1800
      );
    });

    it('should refresh TTL on update', async () => {
      const session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      await store.updateSession(session);

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        'EX',
        1800
      );
    });
  });

  describe('appendMessages', () => {
    it('should append messages and update session', async () => {
      const session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [] as any[],
      };

      const userMsg = { role: 'user' as const, content: 'Hello', timestamp: new Date().toISOString() };
      const assistantMsg = { role: 'assistant' as const, content: 'Hi', timestamp: new Date().toISOString() };

      const updated = await store.appendMessages(session, userMsg, assistantMsg);

      expect(updated.history).toHaveLength(2);
      expect(updated.messageCount).toBe(2);
      expect(mockRedis.set).toHaveBeenCalled();
    });

    it('should trim history when exceeding maxHistoryLength', async () => {
      mockLoadConfig.mockReturnValue({
        session: { timeoutMinutes: 30, maxHistoryLength: 5 },
      } as any);

      const session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 4,
        history: [
          { role: 'user', content: '1', timestamp: new Date().toISOString() },
          { role: 'assistant', content: '2', timestamp: new Date().toISOString() },
          { role: 'user', content: '3', timestamp: new Date().toISOString() },
          { role: 'assistant', content: '4', timestamp: new Date().toISOString() },
        ],
      };

      const userMsg = { role: 'user' as const, content: '5', timestamp: new Date().toISOString() };
      const assistantMsg = { role: 'assistant' as const, content: '6', timestamp: new Date().toISOString() };

      const updated = await store.appendMessages(session, userMsg, assistantMsg);

      expect(updated.history).toHaveLength(5);
      expect(updated.history[0].content).toBe('3'); // First message trimmed
    });

    it('should exclude system messages from messageCount', async () => {
      const session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [
          { role: 'system', content: 'System prompt', timestamp: new Date().toISOString() },
        ],
      };

      const userMsg = { role: 'user' as const, content: 'Test', timestamp: new Date().toISOString() };
      const assistantMsg = { role: 'assistant' as const, content: 'Reply', timestamp: new Date().toISOString() };

      const updated = await store.appendMessages(session, userMsg, assistantMsg);

      expect(updated.messageCount).toBe(2); // System message not counted
    });
  });

  describe('deleteSession', () => {
    it('should delete session from Redis', async () => {
      mockRedis.del.mockResolvedValue(1);

      const deleted = await store.deleteSession('test-id');

      expect(mockRedis.del).toHaveBeenCalledWith('session:test-id');
      expect(deleted).toBe(true);
      expect(logger.info).toHaveBeenCalledWith(
        'Session deleted',
        expect.objectContaining({ sessionId: 'test-id' })
      );
    });

    it('should return false when session does not exist', async () => {
      mockRedis.del.mockResolvedValue(0);

      const deleted = await store.deleteSession('non-existent');

      expect(deleted).toBe(false);
    });
  });

  describe('listSessions', () => {
    it('should return empty array when no sessions exist', async () => {
      mockRedis.scan.mockResolvedValue(['0', []]);

      const sessions = await store.listSessions();

      expect(sessions).toEqual([]);
    });

    it('should list all sessions from Redis', async () => {
      const session1 = {
        id: 'id-1',
        clientName: 'client1',
        threadId: 'thread1',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 0,
        history: [],
      };

      const session2 = {
        id: 'id-2',
        clientName: 'client2',
        threadId: 'thread2',
        createdAt: '2024-01-01T01:00:00.000Z',
        lastActivityAt: '2024-01-01T02:00:00.000Z',
        status: 'active',
        messageCount: 5,
        history: [],
      };

      mockRedis.scan.mockResolvedValue(['0', ['session:id-1', 'session:id-2']]);

      const mockPipeline = {
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [null, JSON.stringify(session1)],
          [null, JSON.stringify(session2)],
        ]),
      };

      mockRedis.pipeline.mockReturnValue(mockPipeline);

      const sessions = await store.listSessions();

      expect(sessions).toHaveLength(2);
      expect(sessions[0]).not.toHaveProperty('history');
      expect(sessions[0]).not.toHaveProperty('threadId');
      expect(mockPipeline.get).toHaveBeenCalledTimes(2);
    });

    it('should handle pagination with SCAN cursor', async () => {
      mockRedis.scan
        .mockResolvedValueOnce(['5', ['session:id-1', 'session:id-2']])
        .mockResolvedValueOnce(['0', ['session:id-3']]);

      const mockPipeline = {
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [null, JSON.stringify({ id: 'id-1', clientName: 'c1', threadId: 't1', status: 'active', messageCount: 0, createdAt: '2024-01-01T00:00:00.000Z', lastActivityAt: '2024-01-01T00:00:00.000Z', history: [] })],
          [null, JSON.stringify({ id: 'id-2', clientName: 'c2', threadId: 't2', status: 'active', messageCount: 0, createdAt: '2024-01-01T00:00:00.000Z', lastActivityAt: '2024-01-01T00:00:00.000Z', history: [] })],
          [null, JSON.stringify({ id: 'id-3', clientName: 'c3', threadId: 't3', status: 'active', messageCount: 0, createdAt: '2024-01-01T00:00:00.000Z', lastActivityAt: '2024-01-01T00:00:00.000Z', history: [] })],
        ]),
      };

      mockRedis.pipeline.mockReturnValue(mockPipeline);

      const sessions = await store.listSessions();

      expect(mockRedis.scan).toHaveBeenCalledTimes(2);
      expect(sessions).toHaveLength(3);
    });

    it('should sort sessions by lastActivityAt descending', async () => {
      const session1 = {
        id: 'id-1',
        clientName: 'c1',
        threadId: 't1',
        status: 'active',
        messageCount: 0,
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T01:00:00.000Z',
        history: [],
      };

      const session2 = {
        id: 'id-2',
        clientName: 'c2',
        threadId: 't2',
        status: 'active',
        messageCount: 0,
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T03:00:00.000Z', // Most recent
        history: [],
      };

      mockRedis.scan.mockResolvedValue(['0', ['session:id-1', 'session:id-2']]);

      const mockPipeline = {
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [null, JSON.stringify(session1)],
          [null, JSON.stringify(session2)],
        ]),
      };

      mockRedis.pipeline.mockReturnValue(mockPipeline);

      const sessions = await store.listSessions();

      expect(sessions[0].id).toBe('id-2'); // Most recent first
      expect(sessions[1].id).toBe('id-1');
    });

    it('should handle Redis errors gracefully', async () => {
      mockRedis.scan.mockResolvedValue(['0', ['session:id-1']]);

      const mockPipeline = {
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [new Error('Redis error'), null],
        ]),
      };

      mockRedis.pipeline.mockReturnValue(mockPipeline);

      const sessions = await store.listSessions();

      expect(sessions).toEqual([]); // Errors are filtered out
    });

    it('should handle null responses from pipeline', async () => {
      mockRedis.scan.mockResolvedValue(['0', ['session:id-1']]);

      const mockPipeline = {
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [null, null], // Session key exists but value is null
        ]),
      };

      mockRedis.pipeline.mockReturnValue(mockPipeline);

      const sessions = await store.listSessions();

      expect(sessions).toEqual([]);
    });
  });
});
