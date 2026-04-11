export type MessageRole = 'user' | 'assistant' | 'system';

export interface Message {
  role: MessageRole;
  content: string;
  timestamp: string; // ISO-8601
}

export type SessionStatus = 'active' | 'expired';

export interface Session {
  id: string;
  clientName: string;
  createdAt: string;       // ISO-8601
  lastActivityAt: string;  // ISO-8601
  status: SessionStatus;
  messageCount: number;
  history: Message[];
  threadId: string;        // Azure AI Foundry thread ID
}

/** Session metadata without the full history or internal Azure details. */
export type SessionSummary = Omit<Session, 'history' | 'threadId'>;
