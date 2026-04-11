export interface SessionSummary {
  id: string;
  clientName: string;
  createdAt: string;
  lastActivityAt: string;
  status: 'active' | 'expired';
  messageCount: number;
}

export interface SessionDetail extends SessionSummary {
  historyLength: number;
  recentMessages: Message[];
}

export interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface ChatReply {
  sessionId: string;
  reply: string;
  messageCount: number;
  lastActivityAt: string;
}

export interface ApiError {
  code: string;
  message: string;
  stack?: string;
}

class ApiClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly apiError: ApiError
  ) {
    super(apiError.message);
  }
}

async function request<T>(
  method: string,
  path: string,
  apiKey: string,
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) headers['X-API-Key'] = apiKey;

  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 204) return undefined as unknown as T;

  const json = await res.json();
  if (!res.ok) {
    throw new ApiClientError(res.status, (json as { error: ApiError }).error);
  }
  return json as T;
}

export function createClient(apiKey: string) {
  return {
    createSession: () =>
      request<{ sessionId: string; clientName: string; createdAt: string; status: string }>(
        'POST', '/sessions', apiKey
      ),
    listSessions: () =>
      request<{ sessions: SessionSummary[]; total: number }>('GET', '/sessions', apiKey),
    getSession: (id: string) =>
      request<SessionDetail>('GET', `/sessions/${id}`, apiKey),
    deleteSession: (id: string) =>
      request<void>('DELETE', `/sessions/${id}`, apiKey),
    sendMessage: (sessionId: string, message: string) =>
      request<ChatReply>('POST', `/sessions/${sessionId}/messages`, apiKey, { message }),
  };
}

export { ApiClientError };
