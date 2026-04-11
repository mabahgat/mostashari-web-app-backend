import { useEffect, useRef, useState } from 'react';
import { Message, SessionDetail, ApiClientError, createClient } from '../api/client';
import { MessageBubble } from './MessageBubble';

interface Props {
  sessionId: string | null;
  apiKey: string;
  onSessionUpdate: () => void;
}

export function ChatPanel({ sessionId, apiKey, onSessionUpdate }: Props) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [session, setSession] = useState<SessionDetail | null>(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [typing, setTyping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const client = createClient(apiKey);

  useEffect(() => {
    if (!sessionId) {
      setMessages([]);
      setSession(null);
      return;
    }
    loadSession(sessionId);
  }, [sessionId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, typing]);

  async function loadSession(id: string) {
    try {
      const detail = await client.getSession(id);
      setSession(detail);
      setMessages(detail.recentMessages);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiClientError ? err.apiError.message : 'Failed to load session');
    }
  }

  async function sendMessage() {
    if (!sessionId || !input.trim() || loading) return;

    const text = input.trim();
    setInput('');
    setLoading(true);
    setTyping(true);
    setError(null);

    const userMsg: Message = { role: 'user', content: text, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const reply = await client.sendMessage(sessionId, text);
      const assistantMsg: Message = {
        role: 'assistant',
        content: reply.reply,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
      setSession((prev) => prev ? { ...prev, messageCount: reply.messageCount, lastActivityAt: reply.lastActivityAt } : prev);
      onSessionUpdate();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.apiError.message : 'Failed to send message');
      setMessages((prev) => prev.slice(0, -1));
    } finally {
      setLoading(false);
      setTyping(false);
      inputRef.current?.focus();
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void sendMessage();
    }
  }

  if (!sessionId) {
    return (
      <div className="flex-1 flex items-center justify-center text-slate-400">
        <div className="text-center">
          <div className="text-5xl mb-4">💬</div>
          <p className="text-lg font-medium">Select or create a session</p>
          <p className="text-sm mt-1">Start a conversation with Azure AI Foundry</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Session header */}
      <div className="px-6 py-3 border-b border-slate-200 bg-white flex items-center justify-between shrink-0">
        <div>
          <p className="text-sm font-semibold text-slate-700">{session?.clientName ?? '…'}</p>
          <p className="text-xs text-slate-400 font-mono">{sessionId}</p>
        </div>
        <div className="text-xs text-slate-400 text-right">
          <p>{session?.messageCount ?? 0} messages</p>
          <p className="mt-0.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1 align-middle" />
            {session?.status ?? 'active'}
          </p>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto scrollbar-thin px-6 py-4">
        {messages.length === 0 && (
          <p className="text-sm text-slate-400 text-center mt-8">
            Send a message to begin the conversation.
          </p>
        )}
        {messages.map((msg, i) => (
          <MessageBubble key={i} message={msg} />
        ))}
        {typing && (
          <div className="flex justify-start mb-3">
            <div className="w-8 h-8 rounded-full bg-violet-100 flex items-center justify-center mr-2 mt-1 shrink-0">
              <span className="text-violet-600 text-xs font-bold">AI</span>
            </div>
            <div className="bg-white border border-slate-100 rounded-2xl rounded-tl-sm px-4 py-3 shadow-sm">
              <div className="flex gap-1 items-center h-4">
                {[0, 1, 2].map((i) => (
                  <span
                    key={i}
                    className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce"
                    style={{ animationDelay: `${i * 150}ms` }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Error banner */}
      {error && (
        <div className="mx-6 mb-2 px-4 py-2 bg-red-50 border border-red-200 rounded-lg text-sm text-red-600 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-600 ml-2">×</button>
        </div>
      )}

      {/* Input bar */}
      <div className="px-6 pb-4 pt-2 border-t border-slate-200 bg-white shrink-0">
        <div className="flex gap-3 items-end bg-slate-50 border border-slate-200 rounded-xl px-4 py-2 focus-within:border-indigo-400 focus-within:ring-1 focus-within:ring-indigo-400 transition-all">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message… (Enter to send, Shift+Enter for newline)"
            rows={1}
            disabled={loading}
            className="flex-1 bg-transparent resize-none outline-none text-sm text-slate-700 placeholder-slate-400 max-h-32 py-1 scrollbar-thin"
            style={{ height: 'auto' }}
            onInput={(e) => {
              const t = e.currentTarget;
              t.style.height = 'auto';
              t.style.height = `${t.scrollHeight}px`;
            }}
          />
          <button
            onClick={() => void sendMessage()}
            disabled={loading || !input.trim()}
            className="shrink-0 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg p-2 transition-colors"
          >
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
              <path d="M3.105 2.288a.75.75 0 00-.826.95l1.414 4.926A1.5 1.5 0 005.135 9.25h6.115a.75.75 0 010 1.5H5.135a1.5 1.5 0 00-1.442 1.086l-1.414 4.926a.75.75 0 00.826.95 28.897 28.897 0 0015.293-7.155.75.75 0 000-1.114A28.897 28.897 0 003.105 2.288z" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}
