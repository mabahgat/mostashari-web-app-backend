#!/usr/bin/env bash
# dev.sh — start the chat backend (and optionally the React UI) in dev mode
#
# Usage:
#   ./dev.sh              — backend + UI (hot-reload for both)
#   ./dev.sh --backend    — backend only (no Vite, no UI)
#
# Backend:  ts-node-dev watches src/**/*.ts  → http://localhost:3000
# UI:       Vite dev server with HMR         → http://localhost:5173/chat/
# Swagger:  served by the backend            → http://localhost:3000/api-docs
#
# Press Ctrl+C to stop everything cleanly.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PORT=3000
UI_PORT=5173

# ── Parse arguments ───────────────────────────────────────────────────────────
START_UI=true
for arg in "$@"; do
  case "$arg" in
    --backend|-b) START_UI=false ;;
    --help|-h)
      echo "Usage: ./dev.sh [--backend]"
      echo "  (no flags)   Start backend + React UI dev server"
      echo "  --backend    Start backend only (no UI)"
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

# ── ANSI colours ──────────────────────────────────────────────────────────────
BOLD='\033[1m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
DIM='\033[2m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { printf "${BOLD}${GREEN}▶${NC}  %s\n"       "$*"; }
warn()    { printf "${YELLOW}⚠  %s${NC}\n"             "$*"; }
error()   { printf "${RED}✖  %s${NC}\n" "$*" >&2; exit 1; }
divider() { printf "${DIM}%s${NC}\n" "────────────────────────────────────────"; }

# Prefix every line from a stream with a coloured tag
prefix_backend() { while IFS= read -r line; do printf "${CYAN}[backend]${NC} %s\n" "$line"; done; }
prefix_ui()      { while IFS= read -r line; do printf "${MAGENTA}[ui]${NC}      %s\n" "$line"; done; }

# ── Cleanup ───────────────────────────────────────────────────────────────────
BACKEND_JOB_PID=0
UI_JOB_PID=0

cleanup() {
  printf "\n${YELLOW}▶ Shutting down...${NC}\n"
  [[ $BACKEND_JOB_PID -ne 0 ]] && kill "$BACKEND_JOB_PID" 2>/dev/null || true
  [[ $UI_JOB_PID      -ne 0 ]] && kill "$UI_JOB_PID"      2>/dev/null || true
  wait 2>/dev/null || true
  printf "${GREEN}✓ All processes stopped.${NC}\n"
}
trap cleanup INT TERM EXIT

# ── Pre-flight checks ─────────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || error "node not found in PATH. Install Node.js 20+ first."
command -v npm  >/dev/null 2>&1 || error "npm not found in PATH."

if [[ ! -f "$SCRIPT_DIR/config.yaml" ]]; then
  warn "config.yaml not found — copying from config.example.yaml"
  cp "$SCRIPT_DIR/config.example.yaml" "$SCRIPT_DIR/config.yaml"
  warn "Edit config.yaml with your Azure credentials before testing chat."
  warn "Backend will start but Azure calls will fail until credentials are set."
  echo ""
fi

# ── Install dependencies if node_modules are missing ─────────────────────────
if [[ ! -d "$SCRIPT_DIR/node_modules" ]]; then
  info "Installing backend dependencies..."
  (cd "$SCRIPT_DIR" && npm install --silent) || error "Backend npm install failed."
fi

if [[ "$START_UI" == true && ! -d "$SCRIPT_DIR/ui/node_modules" ]]; then
  info "Installing UI dependencies..."
  (cd "$SCRIPT_DIR/ui" && npm install --silent) || error "UI npm install failed."
fi

# ── Print banner ──────────────────────────────────────────────────────────────
printf "\n"
divider
if [[ "$START_UI" == true ]]; then
  printf "${BOLD}  Chat Backend — Dev Mode (backend + UI)${NC}\n"
else
  printf "${BOLD}  Chat Backend — Dev Mode (backend only)${NC}\n"
fi
divider
printf "  ${CYAN}[backend]${NC}  ts-node-dev · auto-restart on .ts changes\n"
printf "            API  → ${BOLD}http://localhost:${BACKEND_PORT}${NC}\n"
printf "            Docs → ${BOLD}http://localhost:${BACKEND_PORT}/api-docs${NC}\n"
printf "            Chat → ${BOLD}http://localhost:${BACKEND_PORT}/chat${NC}\n"
if [[ "$START_UI" == true ]]; then
  printf "\n"
  printf "  ${MAGENTA}[ui]${NC}       Vite + React · HMR on component changes\n"
  printf "            Chat → ${BOLD}http://localhost:${UI_PORT}/chat/${NC}\n"
  printf "            (proxies /sessions calls to the backend above)\n"
  printf "\n"
  printf "  ${DIM}Press Ctrl+C to stop both processes.${NC}\n"
else
  printf "\n"
  printf "  ${DIM}Press Ctrl+C to stop the backend.${NC}\n"
fi
divider
printf "\n"

# ── Launch backend ────────────────────────────────────────────────────────────
# ts-node-dev watches src/**/*.ts and restarts the server on every change.
# FORCE_COLOR=1 preserves colour output through the pipe.
(cd "$SCRIPT_DIR" && FORCE_COLOR=1 npm run dev 2>&1 | prefix_backend) &
BACKEND_JOB_PID=$!

if [[ "$START_UI" == true ]]; then
  # Give the backend a moment to bind its port before the Vite proxy starts up.
  sleep 1

  # ── Launch UI dev server ────────────────────────────────────────────────────
  # Vite serves the React app with HMR. Changes to ui/src/** are reflected in
  # the browser instantly without a full reload.
  # FORCE_COLOR=1 preserves Vite's own colour output through the pipe.
  (cd "$SCRIPT_DIR/ui" && FORCE_COLOR=1 npm run dev 2>&1 | prefix_ui) &
  UI_JOB_PID=$!

  wait "$BACKEND_JOB_PID" "$UI_JOB_PID"
else
  wait "$BACKEND_JOB_PID"
fi
