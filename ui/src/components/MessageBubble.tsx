import { Message } from '../api/client';

interface Props {
  message: Message;
}

export function MessageBubble({ message }: Props) {
  const isUser = message.role === 'user';
  const time = new Date(message.timestamp).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-3`}>
      {!isUser && (
        <div className="w-8 h-8 rounded-full bg-violet-100 flex items-center justify-center mr-2 mt-1 shrink-0">
          <span className="text-violet-600 text-xs font-bold">AI</span>
        </div>
      )}
      <div className={`max-w-[75%] ${isUser ? 'items-end' : 'items-start'} flex flex-col`}>
        <div
          className={`px-4 py-2.5 rounded-2xl text-sm leading-relaxed whitespace-pre-wrap break-words shadow-sm ${
            isUser
              ? 'bg-indigo-600 text-white rounded-tr-sm'
              : 'bg-white text-slate-700 rounded-tl-sm border border-slate-100'
          }`}
        >
          {message.content}
        </div>
        <span className="text-xs text-slate-400 mt-1 px-1">{time}</span>
      </div>
      {isUser && (
        <div className="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center ml-2 mt-1 shrink-0">
          <span className="text-indigo-600 text-xs font-bold">You</span>
        </div>
      )}
    </div>
  );
}
