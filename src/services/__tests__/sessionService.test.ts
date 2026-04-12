import {
  createSession,
  getSession,
  updateSession,
  appendMessages,
  deleteSession,
  listSessions,
} from '../sessionService';
import { getSessionStore } from '../sessionStoreFactory';
import { Session, Message } from '../../types';

jest.mock('../sessionStoreFactory');

const mockGetSessionStore = getSessionStore as jest.MockedFunction<typeof getSessionStore>;

describe('services/sessionService', () => {
  let mockStore: any;

  beforeEach(() => {
    mockStore = {
      createSession: jest.fn(),
      getSession: jest.fn(),
      updateSession: jest.fn(),
      appendMessages: jest.fn(),
      deleteSession: jest.fn(),
      listSessions: jest.fn(),
    };

    mockGetSessionStore.mockReturnValue(mockStore);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createSession', () => {
    it('should delegate to store.createSession', async () => {
      const mockSession = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      mockStore.createSession.mockResolvedValue(mockSession);

      const result = await createSession('client', 'thread');

      expect(mockStore.createSession).toHaveBeenCalledWith('client', 'thread');
      expect(result).toEqual(mockSession);
    });
  });

  describe('getSession', () => {
    it('should delegate to store.getSession', async () => {
      const mockSession = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        history: [],
      };

      mockStore.getSession.mockResolvedValue(mockSession);

      const result = await getSession('test-id');

      expect(mockStore.getSession).toHaveBeenCalledWith('test-id');
      expect(result).toEqual(mockSession);
    });

    it('should return null when session not found', async () => {
      mockStore.getSession.mockResolvedValue(null);

      const result = await getSession('non-existent');

      expect(result).toBeNull();
    });
  });

  describe('updateSession', () => {
    it('should delegate to store.updateSession', async () => {
      const session: Session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 0,
        history: [],
      };

      mockStore.updateSession.mockResolvedValue(session);

      const result = await updateSession(session);

      expect(mockStore.updateSession).toHaveBeenCalledWith(session);
      expect(result).toEqual(session);
    });
  });

  describe('appendMessages', () => {
    it('should delegate to store.appendMessages', async () => {
      const session: Session = {
        id: 'test-id',
        clientName: 'client',
        threadId: 'thread',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
        messageCount: 0,
        history: [],
      };

      const userMsg: Message = {
        role: 'user',
        content: 'Hello',
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      const assistantMsg: Message = {
        role: 'assistant',
        content: 'Hi',
        timestamp: '2024-01-01T00:00:01.000Z',
      };

      const updatedSession = { ...session, messageCount: 2, history: [userMsg, assistantMsg] };
      mockStore.appendMessages.mockResolvedValue(updatedSession);

      const result = await appendMessages(session, userMsg, assistantMsg);

      expect(mockStore.appendMessages).toHaveBeenCalledWith(session, userMsg, assistantMsg);
      expect(result).toEqual(updatedSession);
    });
  });

  describe('deleteSession', () => {
    it('should delegate to store.deleteSession', async () => {
      mockStore.deleteSession.mockResolvedValue(true);

      const result = await deleteSession('test-id');

      expect(mockStore.deleteSession).toHaveBeenCalledWith('test-id');
      expect(result).toBe(true);
    });

    it('should return false when session does not exist', async () => {
      mockStore.deleteSession.mockResolvedValue(false);

      const result = await deleteSession('non-existent');

      expect(result).toBe(false);
    });
  });

  describe('listSessions', () => {
    it('should delegate to store.listSessions', async () => {
      const mockSessions = [
        {
          id: 'id-1',
          clientName: 'client1',
          createdAt: '2024-01-01T00:00:00.000Z',
          lastActivityAt: '2024-01-01T00:00:00.000Z',
          status: 'active' as const,
          messageCount: 0,
        },
        {
          id: 'id-2',
          clientName: 'client2',
          createdAt: '2024-01-01T01:00:00.000Z',
          lastActivityAt: '2024-01-01T02:00:00.000Z',
          status: 'active' as const,
          messageCount: 5,
        },
      ];

      mockStore.listSessions.mockResolvedValue(mockSessions);

      const result = await listSessions();

      expect(mockStore.listSessions).toHaveBeenCalled();
      expect(result).toEqual(mockSessions);
    });

    it('should return empty array when no sessions exist', async () => {
      mockStore.listSessions.mockResolvedValue([]);

      const result = await listSessions();

      expect(result).toEqual([]);
    });
  });
});
