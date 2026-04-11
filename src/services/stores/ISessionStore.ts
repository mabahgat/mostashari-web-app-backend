import { Session, SessionSummary, Message } from '../../types';

export interface ISessionStore {
  createSession(clientName: string, threadId: string): Promise<Session>;
  getSession(id: string): Promise<Session | null>;
  updateSession(session: Session): Promise<Session>;
  appendMessages(
    session: Session,
    userMessage: Message,
    assistantMessage: Message
  ): Promise<Session>;
  deleteSession(id: string): Promise<boolean>;
  listSessions(): Promise<SessionSummary[]>;
}
