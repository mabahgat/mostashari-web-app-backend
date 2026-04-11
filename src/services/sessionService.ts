import { getSessionStore } from './sessionStoreFactory';
import { Session, SessionSummary, Message } from '../types';

export async function createSession(clientName: string, threadId: string): Promise<Session> {
  return getSessionStore().createSession(clientName, threadId);
}

export async function getSession(id: string): Promise<Session | null> {
  return getSessionStore().getSession(id);
}

export async function updateSession(session: Session): Promise<Session> {
  return getSessionStore().updateSession(session);
}

export async function appendMessages(
  session: Session,
  userMessage: Message,
  assistantMessage: Message
): Promise<Session> {
  return getSessionStore().appendMessages(session, userMessage, assistantMessage);
}

export async function deleteSession(id: string): Promise<boolean> {
  return getSessionStore().deleteSession(id);
}

export async function listSessions(): Promise<SessionSummary[]> {
  return getSessionStore().listSessions();
}

