import { v4 as uuidv4 } from 'uuid';
import { loadConfig } from '../../config/loader';
import { Session, SessionSummary, Message } from '../../types';
import { ISessionStore } from './ISessionStore';
import logger from '../logger';

interface StoredEntry {
  session: Session;
  timer: ReturnType<typeof setTimeout>;
}

export class InMemorySessionStore implements ISessionStore {
  private readonly store = new Map<string, StoredEntry>();

  private ttlMs(): number {
    const { session } = loadConfig();
    return session.timeoutMinutes * 60 * 1000;
  }

  private scheduleExpiry(id: string): ReturnType<typeof setTimeout> {
    return setTimeout(() => {
      this.store.delete(id);
      logger.debug('In-memory session expired', { sessionId: id });
    }, this.ttlMs());
  }

  private resetTimer(id: string): void {
    const entry = this.store.get(id);
    if (!entry) return;
    clearTimeout(entry.timer);
    entry.timer = this.scheduleExpiry(id);
  }

  private save(session: Session): void {
    const existing = this.store.get(session.id);
    if (existing) {
      clearTimeout(existing.timer);
    }
    const timer = this.scheduleExpiry(session.id);
    this.store.set(session.id, { session, timer });
  }

  async createSession(clientName: string, threadId: string): Promise<Session> {
    const now = new Date().toISOString();
    const session: Session = {
      id: uuidv4(),
      clientName,
      createdAt: now,
      lastActivityAt: now,
      status: 'active',
      messageCount: 0,
      history: [],
      threadId,
    };
    this.save(session);
    logger.info('Session created (in-memory)', { sessionId: session.id, clientName });
    return session;
  }

  async getSession(id: string): Promise<Session | null> {
    return this.store.get(id)?.session ?? null;
  }

  async updateSession(session: Session): Promise<Session> {
    session.lastActivityAt = new Date().toISOString();
    this.save(session);
    return session;
  }

  async appendMessages(
    session: Session,
    userMessage: Message,
    assistantMessage: Message
  ): Promise<Session> {
    const { session: sessionConfig } = loadConfig();
    session.history.push(userMessage, assistantMessage);
    session.messageCount = session.history.filter((m) => m.role !== 'system').length;
    if (session.history.length > sessionConfig.maxHistoryLength) {
      session.history = session.history.slice(session.history.length - sessionConfig.maxHistoryLength);
    }
    return this.updateSession(session);
  }

  async deleteSession(id: string): Promise<boolean> {
    const entry = this.store.get(id);
    if (!entry) return false;
    clearTimeout(entry.timer);
    this.store.delete(id);
    logger.info('Session deleted (in-memory)', { sessionId: id });
    return true;
  }

  async listSessions(): Promise<SessionSummary[]> {
    return Array.from(this.store.values())
      .map(({ session }) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { history: _history, threadId: _threadId, ...summary } = session;
        return summary;
      })
      .sort((a, b) => new Date(b.lastActivityAt).getTime() - new Date(a.lastActivityAt).getTime());
  }
}
