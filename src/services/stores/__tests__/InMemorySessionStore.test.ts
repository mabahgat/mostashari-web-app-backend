import { InMemorySessionStore } from '../../stores/InMemorySessionStore';
import { loadConfig } from '../../../config/loader';
import logger from '../../logger';

jest.mock('../../../config/loader');
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

describe('services/stores/InMemorySessionStore', () => {
  let store: InMemorySessionStore;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    mockLoadConfig.mockReturnValue({
      session: {
        timeoutMinutes: 30,
        maxHistoryLength: 100,
      },
    } as any);
    store = new InMemorySessionStore();
  });

  afterEach(() => {
    jest.useRealTimers();
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
      expect(session.createdAt).toBeDefined();
      expect(session.lastActivityAt).toBeDefined();
    });

    it('should log session creation', async () => {
      await store.createSession('client1', 'thread-abc');

      expect(logger.info).toHaveBeenCalledWith(
        'Session created (in-memory)',
        expect.objectContaining({ clientName: 'client1' })
      );
    });

    it('should schedule automatic expiry', async () => {
      const session = await store.createSession('client', 'thread');

      // Session should exist initially
      const found = await store.getSession(session.id);
      expect(found).not.toBeNull();

      // Fast-forward time beyond TTL (30 minutes)
      jest.advanceTimersByTime(30 * 60 * 1000 + 1000);

      // Session should be expired
      const expired = await store.getSession(session.id);
      expect(expired).toBeNull();
      expect(logger.debug).toHaveBeenCalledWith(
        'In-memory session expired',
        expect.objectContaining({ sessionId: session.id })
      );
    });

    it('should create sessions with unique IDs', async () => {
      const session1 = await store.createSession('client1', 'thread1');
      const session2 = await store.createSession('client2', 'thread2');

      expect(session1.id).not.toBe(session2.id);
    });
  });

  describe('getSession', () => {
    it('should retrieve an existing session', async () => {
      const created = await store.createSession('client', 'thread');
      const retrieved = await store.getSession(created.id);

      expect(retrieved).toEqual(created);
    });

    it('should return null for non-existent session', async () => {
      const result = await store.getSession('00000000-0000-0000-0000-000000000000');

      expect(result).toBeNull();
    });

    it('should return null for expired session', async () => {
      const session = await store.createSession('client', 'thread');

      jest.advanceTimersByTime(30 * 60 * 1000 + 1000);

      const result = await store.getSession(session.id);
      expect(result).toBeNull();
    });
  });

  describe('updateSession', () => {
    it('should update session lastActivityAt', async () => {
      const session = await store.createSession('client', 'thread');
      const originalTime = session.lastActivityAt;

      // Advance time
      jest.advanceTimersByTime(5000);

      session.status = 'active';
      const updated = await store.updateSession(session);

      expect(updated.lastActivityAt).not.toBe(originalTime);
    });

    it('should reset expiry timer on update', async () => {
      const session = await store.createSession('client', 'thread');

      // Advance time partway through TTL
      jest.advanceTimersByTime(20 * 60 * 1000);

      // Update session (should reset timer)
      await store.updateSession(session);

      // Advance 20 more minutes (total 40, but timer was reset at 20)
      jest.advanceTimersByTime(20 * 60 * 1000);

      // Session should still exist because timer was reset
      const found = await store.getSession(session.id);
      expect(found).not.toBeNull();
    });
  });

  describe('appendMessages', () => {
    it('should append user and assistant messages to history', async () => {
      const session = await store.createSession('client', 'thread');
      const userMsg = { role: 'user' as const, content: 'Hello', timestamp: new Date().toISOString() };
      const assistantMsg = { role: 'assistant' as const, content: 'Hi', timestamp: new Date().toISOString() };

      const updated = await store.appendMessages(session, userMsg, assistantMsg);

      expect(updated.history).toHaveLength(2);
      expect(updated.history[0]).toEqual(userMsg);
      expect(updated.history[1]).toEqual(assistantMsg);
      expect(updated.messageCount).toBe(2);
    });

    it('should increment messageCount excluding system messages', async () => {
      const session = await store.createSession('client', 'thread');
      session.history.push({ role: 'system', content: 'System prompt', timestamp: new Date().toISOString() });

      const userMsg = { role: 'user' as const, content: 'Test', timestamp: new Date().toISOString() };
      const assistantMsg = { role: 'assistant' as const, content: 'Reply', timestamp: new Date().toISOString() };

      const updated = await store.appendMessages(session, userMsg, assistantMsg);

      expect(updated.messageCount).toBe(2); // Excludes system message
    });

    it('should trim history when exceeding maxHistoryLength', async () => {
      mockLoadConfig.mockReturnValue({
        session: { timeoutMinutes: 30, maxHistoryLength: 5 },
      } as any);

      const session = await store.createSession('client', 'thread');

      // Add 6 messages (3 pairs)
      for (let i = 0; i < 3; i++) {
        const userMsg = { role: 'user' as const, content: `User ${i}`, timestamp: new Date().toISOString() };
        const assistantMsg = { role: 'assistant' as const, content: `Assistant ${i}`, timestamp: new Date().toISOString() };
        await store.appendMessages(session, userMsg, assistantMsg);
      }

      const retrieved = await store.getSession(session.id);

      expect(retrieved!.history).toHaveLength(5);
      // Should keep the most recent messages
      expect(retrieved!.history[0].content).toBe('User 1');
    });

    it('should update lastActivityAt when appending messages', async () => {
      const session = await store.createSession('client', 'thread');
      const originalTime = session.lastActivityAt;

      jest.advanceTimersByTime(1000);

      const userMsg = { role: 'user' as const, content: 'Test', timestamp: new Date().toISOString() };
      const assistantMsg = { role: 'assistant' as const, content: 'Reply', timestamp: new Date().toISOString() };

      const updated = await store.appendMessages(session, userMsg, assistantMsg);

      expect(updated.lastActivityAt).not.toBe(originalTime);
    });
  });

  describe('deleteSession', () => {
    it('should delete an existing session', async () => {
      const session = await store.createSession('client', 'thread');

      const deleted = await store.deleteSession(session.id);

      expect(deleted).toBe(true);
      expect(logger.info).toHaveBeenCalledWith(
        'Session deleted (in-memory)',
        expect.objectContaining({ sessionId: session.id })
      );

      const found = await store.getSession(session.id);
      expect(found).toBeNull();
    });

    it('should return false for non-existent session', async () => {
      const deleted = await store.deleteSession('00000000-0000-0000-0000-000000000000');

      expect(deleted).toBe(false);
    });

    it('should clear expiry timer on delete', async () => {
      const session = await store.createSession('client', 'thread');

      await store.deleteSession(session.id);

      // Advance past expiry time
      jest.advanceTimersByTime(30 * 60 * 1000 + 1000);

      // The debug log for expiry should not be called since timer was cleared
      const debugCalls = (logger.debug as jest.Mock).mock.calls;
      const expiryCalls = debugCalls.filter(call => call[0] === 'In-memory session expired');
      expect(expiryCalls.length).toBe(0);
    });
  });

  describe('listSessions', () => {
    it('should return empty array when no sessions exist', async () => {
      const sessions = await store.listSessions();

      expect(sessions).toEqual([]);
    });

    it('should list all active sessions', async () => {
      await store.createSession('client1', 'thread1');
      await store.createSession('client2', 'thread2');
      await store.createSession('client3', 'thread3');

      const sessions = await store.listSessions();

      expect(sessions).toHaveLength(3);
    });

    it('should exclude history and threadId from summary', async () => {
      const session = await store.createSession('client', 'thread');
      session.history.push({
        role: 'user',
        content: 'Test',
        timestamp: new Date().toISOString(),
      });
      await store.updateSession(session);

      const sessions = await store.listSessions();

      expect(sessions[0]).not.toHaveProperty('history');
      expect(sessions[0]).not.toHaveProperty('threadId');
      expect(sessions[0]).toHaveProperty('id');
      expect(sessions[0]).toHaveProperty('clientName');
      expect(sessions[0]).toHaveProperty('messageCount');
    });

    it('should sort sessions by lastActivityAt descending', async () => {
      const session1 = await store.createSession('client1', 'thread1');
      jest.advanceTimersByTime(1000);
      const session2 = await store.createSession('client2', 'thread2');
      jest.advanceTimersByTime(1000);
      const session3 = await store.createSession('client3', 'thread3');

      const sessions = await store.listSessions();

      expect(sessions[0].id).toBe(session3.id); // Most recent
      expect(sessions[1].id).toBe(session2.id);
      expect(sessions[2].id).toBe(session1.id); // Oldest
    });

    it('should not include expired sessions', async () => {
      const session1 = await store.createSession('client1', 'thread1');
      const session2 = await store.createSession('client2', 'thread2');

      // Expire first session
      jest.advanceTimersByTime(30 * 60 * 1000 + 1000);

      const sessions = await store.listSessions();

      expect(sessions).toHaveLength(1);
      expect(sessions[0].id).toBe(session2.id);
    });
  });
});
