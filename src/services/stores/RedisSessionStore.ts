import { v4 as uuidv4 } from 'uuid';
import { getRedisClient } from '../redisService';
import { loadConfig } from '../../config/loader';
import { Session, SessionSummary, Message } from '../../types';
import { ISessionStore } from './ISessionStore';
import logger from '../logger';

const SESSION_KEY_PREFIX = 'session:';

export class RedisSessionStore implements ISessionStore {
  private sessionKey(id: string): string {
    return `${SESSION_KEY_PREFIX}${id}`;
  }

  private ttlSeconds(): number {
    const { session } = loadConfig();
    return session.timeoutMinutes * 60;
  }

  private async save(session: Session): Promise<void> {
    const redis = getRedisClient();
    await redis.set(this.sessionKey(session.id), JSON.stringify(session), 'EX', this.ttlSeconds());
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
    await this.save(session);
    logger.info('Session created', { sessionId: session.id, clientName });
    return session;
  }

  async getSession(id: string): Promise<Session | null> {
    const redis = getRedisClient();
    const raw = await redis.get(this.sessionKey(id));
    return raw ? (JSON.parse(raw) as Session) : null;
  }

  async updateSession(session: Session): Promise<Session> {
    session.lastActivityAt = new Date().toISOString();
    await this.save(session);
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
    const redis = getRedisClient();
    const deleted = await redis.del(this.sessionKey(id));
    if (deleted > 0) {
      logger.info('Session deleted', { sessionId: id });
      return true;
    }
    return false;
  }

  async listSessions(): Promise<SessionSummary[]> {
    const redis = getRedisClient();
    let cursor = '0';
    const keys: string[] = [];

    do {
      const [nextCursor, batch] = await redis.scan(cursor, 'MATCH', `${SESSION_KEY_PREFIX}*`, 'COUNT', 100);
      cursor = nextCursor;
      keys.push(...batch);
    } while (cursor !== '0');

    if (keys.length === 0) return [];

    const pipeline = redis.pipeline();
    keys.forEach((k) => pipeline.get(k));
    const results = await pipeline.exec();

    const sessions: SessionSummary[] = [];
    results?.forEach(([err, raw]) => {
      if (err || !raw) return;
      const session = JSON.parse(raw as string) as Session;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { history: _history, threadId: _threadId, ...summary } = session;
      sessions.push(summary);
    });

    return sessions.sort(
      (a, b) => new Date(b.lastActivityAt).getTime() - new Date(a.lastActivityAt).getTime()
    );
  }
}
