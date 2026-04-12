import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createClient, ApiClientError } from '../client';

describe('api/client', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  const mockApiKey = 'test-api-key';

  beforeEach(() => {
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('createSession', () => {
    it('should create a new session successfully', async () => {
      const mockResponse = {
        sessionId: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        status: 'active',
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(mockResponse), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);
      const result = await client.createSession();

      expect(fetchSpy).toHaveBeenCalledWith('/sessions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': mockApiKey,
        },
        body: undefined,
      });
      expect(result).toEqual(mockResponse);
    });

    it('should throw ApiClientError on failure', async () => {
      const errorResponse = {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid API key',
        },
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(errorResponse), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);

      await expect(client.createSession()).rejects.toThrow(ApiClientError);
      await expect(client.createSession()).rejects.toThrow('Invalid API key');
    });
  });

  describe('listSessions', () => {
    it('should list all sessions', async () => {
      const mockResponse = {
        sessions: [
          {
            id: 'session-1',
            clientName: 'client1',
            createdAt: '2024-01-01T00:00:00.000Z',
            lastActivityAt: '2024-01-01T00:00:00.000Z',
            status: 'active' as const,
            messageCount: 5,
          },
        ],
        total: 1,
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);
      const result = await client.listSessions();

      expect(fetchSpy).toHaveBeenCalledWith('/sessions', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': mockApiKey,
        },
        body: undefined,
      });
      expect(result).toEqual(mockResponse);
    });

    it('should handle empty session list', async () => {
      const mockResponse = { sessions: [], total: 0 };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);
      const result = await client.listSessions();

      expect(result.sessions).toEqual([]);
      expect(result.total).toBe(0);
    });
  });

  describe('getSession', () => {
    it('should get session details', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 2,
        historyLength: 2,
        recentMessages: [
          { role: 'user' as const, content: 'Hello', timestamp: '2024-01-01T00:00:00.000Z' },
          { role: 'assistant' as const, content: 'Hi', timestamp: '2024-01-01T00:00:01.000Z' },
        ],
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(mockSession), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);
      const result = await client.getSession('session-123');

      expect(fetchSpy).toHaveBeenCalledWith('/sessions/session-123', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': mockApiKey,
        },
        body: undefined,
      });
      expect(result).toEqual(mockSession);
    });

    it('should throw 404 for non-existent session', async () => {
      const errorResponse = {
        error: { code: 'NOT_FOUND', message: 'Session not found' },
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(errorResponse), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);

      await expect(client.getSession('nonexistent')).rejects.toThrow(ApiClientError);
    });
  });

  describe('deleteSession', () => {
    it('should delete a session successfully', async () => {
      fetchSpy.mockResolvedValue(new Response(null, { status: 204 }));

      const client = createClient(mockApiKey);
      const result = await client.deleteSession('session-123');

      expect(fetchSpy).toHaveBeenCalledWith('/sessions/session-123', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': mockApiKey,
        },
        body: undefined,
      });
      expect(result).toBeUndefined();
    });

    it('should handle 404 when deleting non-existent session', async () => {
      const errorResponse = {
        error: { code: 'NOT_FOUND', message: 'Session not found' },
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(errorResponse), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);

      await expect(client.deleteSession('nonexistent')).rejects.toThrow(ApiClientError);
    });
  });

  describe('sendMessage', () => {
    it('should send a message and receive a reply', async () => {
      const mockReply = {
        sessionId: 'session-123',
        reply: 'AI response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(mockReply), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);
      const result = await client.sendMessage('session-123', 'Hello');

      expect(fetchSpy).toHaveBeenCalledWith('/sessions/session-123/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': mockApiKey,
        },
        body: JSON.stringify({ message: 'Hello' }),
      });
      expect(result).toEqual(mockReply);
    });

    it('should handle validation errors', async () => {
      const errorResponse = {
        error: {
          code: 'VALIDATION_ERROR',
          message: 'message must not be empty',
        },
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(errorResponse), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);

      await expect(client.sendMessage('session-123', '')).rejects.toThrow(ApiClientError);
    });

    it('should handle upstream errors', async () => {
      const errorResponse = {
        error: {
          code: 'UPSTREAM_ERROR',
          message: 'Azure AI Foundry error',
        },
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(errorResponse), {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);

      await expect(client.sendMessage('session-123', 'Test')).rejects.toThrow(ApiClientError);
    });
  });

  describe('ApiClientError', () => {
    it('should create error with status and apiError', async () => {
      const errorResponse = {
        error: {
          code: 'CUSTOM_CODE',
          message: 'Custom error message',
          stack: 'Error stack...',
        },
      };

      fetchSpy.mockResolvedValue(new Response(JSON.stringify(errorResponse), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient(mockApiKey);

      try {
        await client.createSession();
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ApiClientError);
        const apiError = err as ApiClientError;
        expect(apiError.status).toBe(500);
        expect(apiError.apiError.code).toBe('CUSTOM_CODE');
        expect(apiError.apiError.message).toBe('Custom error message');
        expect(apiError.apiError.stack).toBe('Error stack...');
        expect(apiError.message).toBe('Custom error message');
      }
    });
  });

  describe('request function edge cases', () => {
    it('should handle requests without API key', async () => {
      const mockResponse = { data: 'test' };
      fetchSpy.mockResolvedValue(new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }));

      const client = createClient('');
      await client.listSessions();

      const callArgs = fetchSpy.mock.calls[0];
      expect(callArgs[1]?.headers).not.toHaveProperty('X-API-Key');
    });
  });
});
