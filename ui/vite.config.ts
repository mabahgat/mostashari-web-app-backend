import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { ServerResponse } from 'http';

/** Write a JSON error response through the raw Node ServerResponse. */
function sendJsonError(res: ServerResponse, status: number, code: string, message: string) {
  if (res.headersSent) return;
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: { code, message } }));
}

/** Shared proxy error handler — returns a 503 instead of letting Vite crash. */
function onProxyError(err: Error, _req: unknown, res: ServerResponse) {
  const msg =
    (err as NodeJS.ErrnoException).code === 'ECONNREFUSED'
      ? 'Backend is not running. Start it with: ./dev.sh'
      : err.message;
  sendJsonError(res, 503, 'BACKEND_UNAVAILABLE', msg);
}

export default defineConfig({
  plugins: [react()],
  base: '/chat/',
  build: {
    outDir: '../src/ui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/sessions': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('error', onProxyError);
        },
      },
      '/health': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('error', onProxyError);
        },
      },
    },
  },
});
