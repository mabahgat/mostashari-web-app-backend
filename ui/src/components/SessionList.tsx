import { SessionSummary } from '../api/client';

interface Props {
  sessions: SessionSummary[];
  activeSessionId: string | null;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onDelete: (id: string) => void;
  loading: boolean;
}

function timeAgo(isoDate: string): string {
  const diff = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function SessionList({ sessions, activeSessionId, onSelect, onCreate, onDelete, loading }: Props) {
  return (
    <aside className="w-72 shrink-0 bg-white border-r border-slate-200 flex flex-col">
      <div className="p-4 border-b border-slate-200">
        <h2 className="text-sm font-semibold text-slate-600 uppercase tracking-wider mb-3">
          Sessions
        </h2>
        <button
          onClick={onCreate}
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-medium py-2 px-4 rounded-lg transition-colors"
        >
          <span className="text-lg leading-none">+</span>
          New Session
        </button>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin p-2 space-y-1">
        {sessions.length === 0 && !loading && (
          <p className="text-xs text-slate-400 text-center py-8 px-4">
            No sessions yet.<br />Click <strong>New Session</strong> to start chatting.
          </p>
        )}
        {sessions.map((s) => (
          <div
            key={s.id}
            onClick={() => onSelect(s.id)}
            className={`group relative cursor-pointer rounded-lg p-3 transition-colors ${
              s.id === activeSessionId
                ? 'bg-indigo-50 border border-indigo-200'
                : 'hover:bg-slate-50 border border-transparent'
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium text-slate-700 truncate">
                  {s.clientName}
                </p>
                <p className="text-xs text-slate-400 font-mono mt-0.5 truncate">
                  {s.id.slice(0, 8)}…
                </p>
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); onDelete(s.id); }}
                className="opacity-0 group-hover:opacity-100 text-slate-300 hover:text-red-400 transition-opacity text-lg leading-none p-0.5"
                title="Delete session"
              >
                ×
              </button>
            </div>
            <div className="flex items-center justify-between mt-2">
              <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${
                s.status === 'active' ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-500'
              }`}>
                {s.status}
              </span>
              <span className="text-xs text-slate-400">
                {s.messageCount} msg{s.messageCount !== 1 ? 's' : ''} · {timeAgo(s.lastActivityAt)}
              </span>
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
