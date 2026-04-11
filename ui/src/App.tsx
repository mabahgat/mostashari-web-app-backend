import { useState, useEffect, useCallback } from 'react';
import { SessionList } from './components/SessionList';
import { ChatPanel } from './components/ChatPanel';
import { SessionSummary, createClient, ApiClientError } from './api/client';

export default function App() {
  const [apiKey, setApiKey] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [globalError, setGlobalError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [backendDown, setBackendDown] = useState(false);

  const fetchSessions = useCallback(async (key: string, silent = false) => {
    const client = createClient(key);
    try {
      const { sessions: list } = await client.listSessions();
      setSessions(list);
      setConnected(true);
      setBackendDown(false);
      setGlobalError(null);
      // Auto-select the most recently active session if none is open yet
      if (list.length > 0) {
        setActiveSessionId((current) => current ?? list[0].id);
      }
    } catch (err) {
      setConnected(false);
      if (err instanceof ApiClientError && err.status === 503) {
        setBackendDown(true);
        if (!silent) setGlobalError('Backend is not running. Start it with ./dev.sh');
      } else if (!silent) {
        setBackendDown(false);
        if (err instanceof ApiClientError && err.status === 401) {
          setGlobalError('Invalid API key. Please check your key and try again.');
        } else {
          setGlobalError('Cannot reach the server. Is it running?');
        }
      }
    }
  }, []);

  // Probe the server on mount with an empty key.
  // In dev mode on localhost the auth middleware auto-authenticates, so this
  // connects immediately without a key. In other modes it fails silently and
  // the user is prompted for a key.
  useEffect(() => {
    void fetchSessions('', true);
  }, [fetchSessions]);

  // When the backend is down, retry every 5 seconds automatically.
  useEffect(() => {
    if (!backendDown) return;
    const interval = setInterval(() => void fetchSessions(apiKey, true), 5000);
    return () => clearInterval(interval);
  }, [backendDown, apiKey, fetchSessions]);

  function handleConnect(e: React.FormEvent) {
    e.preventDefault();
    setApiKey(apiKeyInput);
    void fetchSessions(apiKeyInput);
  }

  async function handleCreateSession() {
    setLoadingSessions(true);
    try {
      const client = createClient(apiKey);
      const { sessionId } = await client.createSession();
      await fetchSessions(apiKey);
      setActiveSessionId(sessionId);
      setGlobalError(null);
    } catch (err) {
      setGlobalError(err instanceof ApiClientError ? err.apiError.message : 'Failed to create session');
    } finally {
      setLoadingSessions(false);
    }
  }

  async function handleDeleteSession(id: string) {
    try {
      const client = createClient(apiKey);
      await client.deleteSession(id);
      setSessions((prev) => prev.filter((s) => s.id !== id));
      if (activeSessionId === id) setActiveSessionId(null);
      setGlobalError(null);
    } catch (err) {
      setGlobalError(err instanceof ApiClientError ? err.apiError.message : 'Failed to delete session');
    }
  }

  return (
    <div className="h-screen flex flex-col bg-slate-50">
      {/* Top bar */}
      <header className="bg-white border-b border-slate-200 px-6 py-3 flex items-center gap-4 shrink-0 shadow-sm">
        <div className="flex items-center gap-2.5 mr-4">
          <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="white" className="w-4 h-4">
              <path fillRule="evenodd" d="M10 2c-2.236 0-4.43.18-6.57.524C1.993 2.755 1 4.014 1 5.426v5.148c0 1.413.993 2.67 2.43 2.902.848.137 1.705.248 2.57.331v3.443a.75.75 0 001.28.53l3.58-3.579a.78.78 0 01.527-.224 41.202 41.202 0 005.183-.5c1.437-.232 2.43-1.49 2.43-2.903V5.426c0-1.413-.993-2.67-2.43-2.902A41.289 41.289 0 0010 2zm0 7a1 1 0 100-2 1 1 0 000 2zM6 9a1 1 0 11-2 0 1 1 0 012 0zm5 1a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
            </svg>
          </div>
          <h1 className="text-sm font-bold text-slate-800">Chat Test UI</h1>
        </div>

        {!connected ? (
          <form onSubmit={handleConnect} className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative flex-1">
              <input
                type="password"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                placeholder="Enter API key (skip in dev mode)"
                className="w-full text-sm border border-slate-200 rounded-lg px-3 py-1.5 pr-8 outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 transition-all"
                autoComplete="off"
              />
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" className="w-3.5 h-3.5 absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400">
                <path fillRule="evenodd" d="M8 1a3.5 3.5 0 00-3.5 3.5V7A1.5 1.5 0 003 8.5v5A1.5 1.5 0 004.5 15h7a1.5 1.5 0 001.5-1.5v-5A1.5 1.5 0 0011.5 7V4.5A3.5 3.5 0 008 1zm2 6V4.5a2 2 0 10-4 0V7h4z" clipRule="evenodd" />
              </svg>
            </div>
            <button
              type="submit"
              className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium px-3 py-1.5 rounded-lg transition-colors shrink-0"
            >
              Connect
            </button>
          </form>
        ) : (
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-full font-medium border border-emerald-200">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              Connected
            </span>
            <button
              onClick={() => { setConnected(false); setApiKey(''); setSessions([]); setActiveSessionId(null); }}
              className="text-xs text-slate-400 hover:text-slate-600 transition-colors"
            >
              Disconnect
            </button>
          </div>
        )}

        {globalError && (
          <div className="ml-auto text-xs text-red-600 bg-red-50 border border-red-200 px-3 py-1.5 rounded-lg flex items-center gap-2">
            <span>{globalError}</span>
            <button onClick={() => setGlobalError(null)} className="text-red-400 hover:text-red-600">×</button>
          </div>
        )}

        <a
          href="/api-docs"
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto text-xs text-slate-500 hover:text-indigo-600 flex items-center gap-1 transition-colors shrink-0"
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" className="w-3.5 h-3.5">
            <path d="M7.25 3.688L2.5 5.25v5.5l4.75 1.562v-8.624zM8.75 12.312L13.5 10.75V5.25L8.75 3.688v8.624z" />
          </svg>
          API Docs
        </a>
      </header>

      {/* Backend unavailable banner */}
      {backendDown && (
        <div className="bg-amber-50 border-b border-amber-200 px-6 py-2 flex items-center gap-2 text-sm text-amber-800 shrink-0">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4 text-amber-500 shrink-0">
            <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
          </svg>
          <span>Backend is not running.</span>
          <code className="bg-amber-100 px-1.5 py-0.5 rounded font-mono text-xs">./dev.sh</code>
          <span>or</span>
          <code className="bg-amber-100 px-1.5 py-0.5 rounded font-mono text-xs">npm run dev</code>
          <button
            onClick={() => void fetchSessions(apiKey, true)}
            className="ml-auto text-xs font-medium text-amber-700 hover:text-amber-900 underline underline-offset-2"
          >
            Retry
          </button>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {connected ? (
          <>
            <SessionList
              sessions={sessions}
              activeSessionId={activeSessionId}
              onSelect={setActiveSessionId}
              onCreate={() => void handleCreateSession()}
              onDelete={(id) => void handleDeleteSession(id)}
              loading={loadingSessions}
            />
            <main className="flex-1 flex flex-col min-w-0">
              <ChatPanel
                sessionId={activeSessionId}
                apiKey={apiKey}
                onSessionUpdate={() => void fetchSessions(apiKey)}
              />
            </main>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center max-w-sm">
              <div className="text-5xl mb-4">🔑</div>
              <h2 className="text-lg font-semibold text-slate-700 mb-2">Enter your API key</h2>
              <p className="text-sm text-slate-500">
                Enter your API key in the header to connect, or leave it blank if running in{' '}
                <code className="bg-slate-100 px-1 py-0.5 rounded text-xs font-mono text-indigo-600">dev</code>{' '}
                mode on localhost.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
