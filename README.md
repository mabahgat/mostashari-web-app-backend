# Chat Backend

A Node.js + TypeScript REST API that forwards chat messages to **Azure AI Foundry Agents**, maintains per-session conversation threads, authenticates callers via named API keys, and ships with a Swagger explorer and a React chat test UI.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Dev Mode — Hot-Reload](#dev-mode--hot-reload)
  - [Backend + UI (default)](#backend--ui-default)
  - [Backend only](#backend-only)
- [Modes](#modes)
- [Configuration (`config.yaml`)](#configuration-configyaml)
- [Azure AI Foundry Authentication](#azure-ai-foundry-authentication)
  - [Local development](#local-development)
  - [CI / Production (Service Principal)](#ci--production-service-principal)
  - [Azure-hosted](#azure-hosted-app-service-container-apps-aks)
- [Caller Authentication (Backend API Keys)](#caller-authentication-backend-api-keys)
- [Project Structure](#project-structure)
- [User Interfaces](#user-interfaces)
  - [API Explorer](#api-explorer--httplocalhost3000api-docs)
  - [Chat Test UI](#chat-test-ui--httplocalhost3000chat)
- [API Reference](#api-reference)
  - [Endpoints overview](#endpoints-overview)
  - [`GET /health`](#get-health)
  - [`POST /generate`](#post-generate)
  - [`POST /search`](#post-search)
  - [`POST /sessions`](#post-sessions)
  - [`POST /sessions/:id/messages`](#post-sessionsidmessages)
  - [`GET /sessions`](#get-sessions)
  - [`GET /sessions/:id`](#get-sessionsid)
  - [`DELETE /sessions/:id`](#delete-sessionsid)
- [Error Responses](#error-responses)
  - [Complete error code reference](#complete-error-code-reference)
  - [Rate limit response headers](#rate-limit-response-headers)
- [CORS](#cors)
- [Search Configuration](#search-configuration)
- [Safeguards Reference](#safeguards-reference)
- [Session Lifetime](#session-lifetime)
- [Testing with curl](#testing-with-curl)
  - [Dev mode](#dev-mode-localhost--no-api-key-needed)
  - [Stage / Prod mode](#stage--prod-mode-api-key-required)
  - [Multi-turn conversation walkthrough](#complete-multi-turn-conversation-walkthrough)
  - [Testing error responses](#testing-error-responses)
- [npm Scripts](#npm-scripts)
- [Running Tests](#running-tests)
  - [Backend Tests (Jest)](#backend-tests-jest)
  - [Frontend Tests (Vitest)](#frontend-tests-vitest)

---

## Features

- **Azure AI Foundry Agents** — thread-per-session model; one persistent agent is created at startup and Azure manages conversation history inside each thread
- **Multi-session management** — independent sessions per client, each mapped to a dedicated Azure thread
- **Named API key auth** — multiple per-client keys configured in YAML; automatic localhost bypass in `dev` mode
- **Three runtime modes** — `dev`, `stage`, `prod` controlling logging verbosity, session storage backend, and error detail
- **Pluggable session storage** — in-memory (`dev`) or Redis (`stage`/`prod`), selected automatically
- **Abuse safeguards** — configurable rate limiting, session caps, message length limit, request body size limit, Azure call timeout
- **Swagger UI** at `/api-docs` — OpenAPI 3.0 spec, try-it-out enabled
- **React Chat UI** at `/chat` — multi-turn interactive chat test interface
- **External YAML config** — all settings in one file, nothing hardcoded

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Node.js 20+ | Required |
| Redis 6+ | Only in `stage` and `prod` modes |
| Azure AI Foundry project | A deployed model and a project endpoint |
| Azure CLI (`az`) | For local Entra ID auth — run `az login` once |
| `jq` *(optional)* | For pretty-printing curl output |

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Setup

```bash
# 1. Install backend dependencies
npm install

# 2. Build the React chat UI (required before first run)
npm run build:ui

# 3. Create your config file — never commit this
cp config.example.yaml config.yaml
# Edit config.yaml with your Azure project endpoint, deployment name, and API keys

# 4. Log in to Azure (required once — used for Entra ID auth to Azure AI Foundry)
az login

# 5. Start the server
npm run dev              # dev mode: hot-reload, in-memory sessions, no Redis
./dev.sh --backend       # same via dev.sh (backend only)
./dev.sh                 # backend + React UI hot-reload
npm run build:all && npm start   # production build + start
```

The server starts on `http://localhost:3000` by default.

> **Config path override:** set `CONFIG_PATH=/path/to/config.yaml` to load the config from a custom location.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Dev Mode — Hot-Reload

**Sections:** [Backend + UI (default)](#backend--ui-default) · [Backend only](#backend-only)

`dev.sh` supports two modes — backend-only, or backend + UI together.

```bash
./dev.sh              # backend + React UI (default)
./dev.sh --backend    # backend only — no Vite, no UI
./dev.sh --help       # show usage
```

### Backend + UI (default)

```bash
./dev.sh
# or equivalently:
npm run dev:all
```

| Process | Watches | URL |
|---------|---------|-----|
| `[backend]` ts-node-dev | `src/**/*.ts` — restarts on every change | `http://localhost:3000` |
| `[ui]` Vite HMR | `ui/src/**` — updates in-browser instantly | `http://localhost:5173/chat/` |

### Backend only

```bash
./dev.sh --backend
# or equivalently:
npm run dev
```

Only the backend ts-node-dev process starts. Useful when you don't need the React UI — faster startup, no Vite process. The Chat UI is still served statically from `http://localhost:3000/chat` if you've run `npm run build:ui` previously.

---

Output from both processes is shown in the same terminal, prefixed and coloured:

```
[backend] Server starting in [dev] mode...
[backend] Chat backend listening on http://0.0.0.0:3000
[ui]      VITE v5.x  ready in 300ms
[ui]      ➜  Local: http://localhost:5173/chat/
```

The script also:
- Installs `node_modules` automatically if missing (backend and/or UI as needed)
- Copies `config.example.yaml` → `config.yaml` if no config is found (with a warning)
- Stops all started processes cleanly on **Ctrl+C**

> **Note:** during hot-reload development, access the Chat UI at `http://localhost:5173/chat/` (Vite HMR). The Vite server proxies all `/sessions` calls to the backend on port 3000, so the `dev` mode localhost auth bypass works transparently.
>
> The Swagger UI at `http://localhost:3000/api-docs` is always served directly by the backend.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Modes

Set `mode:` in `config.yaml`. Defaults to `dev`.

| Mode | Log level & format | Session storage | Stack trace in error responses |
|------|-------------------|-----------------|-------------------------------|
| `dev` *(default)* | `debug`, pretty coloured console | **In-memory** — lost on restart, no Redis | ✅ included |
| `stage` | `debug`, pretty coloured console | Redis | ✅ included |
| `prod` | `info`, JSON (log-aggregator friendly) | Redis | ❌ hidden |

In `dev` mode on localhost, **no API key is required** — all requests are auto-authenticated as `dev-local`. This makes it easy to test with curl or the Chat UI without any credentials.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Configuration (`config.yaml`)

All settings are read at startup from `config.yaml` (or the path in `$CONFIG_PATH`).

```yaml
# Runtime mode: dev | stage | prod  (default: dev)
mode: dev

server:
  port: 3000
  host: "0.0.0.0"

auth:
  # At least one key required. Name is used as the caller identity in logs.
  apiKeys:
    - name: "client-a"
      key: "replace-with-a-strong-random-key"
    - name: "client-b"
      key: "replace-with-another-strong-random-key"

azure:
  # Full Azure AI Foundry project endpoint.
  # Find it: AI Foundry portal → your project → Overview → Libraries → copy the "AI Foundry" endpoint
  # Format: https://<AIFoundryResourceName>.services.ai.azure.com/api/projects/<ProjectName>
  projectEndpoint: "https://<your-foundry-resource>.services.ai.azure.com/api/projects/<your-project>"

  # The model deployment name — find it under Models + endpoints → Name column.
  deployment: "gpt-4o"

  # Display name for the agent in Azure AI Foundry (reused if already exists).
  agentName: "chat-backend-agent"

  maxTokens: 2048
  temperature: 0.7    # 0 = deterministic, 1 = balanced, 2 = very creative
  systemPrompt: "You are a helpful assistant."

# Redis is only used in stage and prod modes
redis:
  host: "localhost"
  port: 6379
  password: ""    # omit or leave empty if no password
  db: 0

session:
  timeoutMinutes: 30     # TTL resets on every message; session expires after this much idle time
  maxHistoryLength: 100  # oldest messages are dropped when this limit is reached

safeguards:
  requestBodyLimitKb: 64        # Max request body size; returns 413 if exceeded
  rateLimitWindowMs: 60000      # Rate limit window in milliseconds
  rateLimitMaxRequests: 60      # Max requests per IP per window → 429
  sessionCreateLimitMax: 10     # Max POST /sessions per IP per window → 429
  maxMessageChars: 4000         # Max characters in a message body → 400
  maxSessionsPerClient: 10      # Max concurrent sessions per API key → 429
  maxTotalSessions: 200         # Hard cap on all sessions server-wide → 429
  azureTimeoutMs: 30000         # Azure call timeout in ms; returns 504 on expiry

cors:
  # Origins allowed to call this API from a browser.
  # In dev mode, all localhost origins (any port) are always allowed automatically.
  # For other modes, list every origin your web app may be served from.
  # Use ["*"] to allow all origins — not recommended for production.
  allowedOrigins:
    - "http://localhost:8000"
    # - "https://myapp.example.com"
  allowCredentials: true   # must be false when allowedOrigins contains "*"

search:
  dnsSuffix: "search.windows.net"
  apiVersion: "2023-11-01"

  # Used when mode="regulations" in POST /search
  regulations:
    service: "your-search-service-name"   # <service>.search.windows.net
    key: "your-search-api-key"
    index: "your-regulations-index-name"
    semanticConfig: "your-regulations-semantic-config"  # omit to disable semantic search

  # Used when mode="cases" in POST /search
  cases:
    service: "your-search-service-name"
    key: "your-search-api-key"
    index: "your-cases-index-name"
    semanticConfig: "your-cases-semantic-config"
```

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Azure AI Foundry Authentication

**Sections:** [Local development](#local-development) · [CI / Production (Service Principal)](#ci--production-service-principal) · [Azure-hosted](#azure-hosted-app-service-container-apps-aks)

The Azure AI Foundry Agents API requires **Entra ID (Azure AD) authentication** — API keys are **not accepted** for this service endpoint.

### Local development

```bash
az login
# Authenticates using your Azure user account. Credentials are cached by the Azure CLI.
# The app picks these up automatically via DefaultAzureCredential.
```

Your account must have the **Azure AI User** or **Contributor** role on the Azure AI Foundry project resource. Assign via:
> Azure Portal → your AI Foundry resource → Access Control (IAM) → Add role assignment

### CI / Production (Service Principal)

**Steps:** [1 — App Registration](#step-1--create-an-app-registration) · [2 — Client Secret](#step-2--create-a-client-secret) · [3 — Grant access](#step-3--grant-the-service-principal-access-to-ai-foundry) · [4 — Set env vars](#step-4--set-the-environment-variables)

#### Step 1 — Create an App Registration

1. Go to **Azure Portal → Microsoft Entra ID → App registrations**
2. Click **New registration**, give it a name (e.g. `chat-backend-ci`), click **Register**
3. On the overview page, copy:

| Variable | Where to find it |
|----------|-----------------|
| `AZURE_TENANT_ID` | **Directory (tenant) ID** on the App Registration overview |
| `AZURE_CLIENT_ID` | **Application (client) ID** on the App Registration overview |

#### Step 2 — Create a Client Secret

1. In the App Registration → **Certificates & secrets → Client secrets**
2. Click **New client secret**, set an expiry, click **Add**
3. Copy the **Value** immediately — it is only shown once

| Variable | Where to find it |
|----------|-----------------|
| `AZURE_CLIENT_SECRET` | The `Value` column right after creation |

#### Step 3 — Grant the service principal access to AI Foundry

1. Azure Portal → your **Azure AI Foundry resource** (the `services.ai.azure.com` resource)
2. **Access Control (IAM) → Add role assignment**
3. Role: **Azure AI User** (or **Contributor** for full access)
4. Assign to: **User, group, or service principal** → search for the App Registration name created above

#### Step 4 — Set the environment variables

```bash
export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_SECRET="your~secret~value"
```

`DefaultAzureCredential` picks these up automatically on startup — no code changes needed.

### Azure-hosted (App Service, Container Apps, AKS)

Enable Managed Identity on the compute resource and assign it the required role. No environment variables or credentials needed.

> **Note:** `azure.projectEndpoint` must use the format
> `https://<ResourceName>.services.ai.azure.com/api/projects/<ProjectName>`
> — this is different from a classic Azure OpenAI endpoint.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Caller Authentication (Backend API Keys)

All `/sessions` endpoints require the `X-API-Key` header:

```
X-API-Key: your-secret-key
```

The key is matched against `auth.apiKeys` in `config.yaml`. On a match, the corresponding `name` is recorded as the `clientName` for that session. Use strong random values (e.g. `openssl rand -hex 32`).

**Dev mode exception:** in `dev` mode, requests arriving from `127.0.0.1` / `::1` are auto-authenticated as `clientName = "dev-local"` with **no key required**. This covers:
- `curl` from the same machine
- The React Chat UI at `localhost:5173` (via Vite proxy)
- Any HTTP client connecting to localhost

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Project Structure

```
├── src/
│   ├── config/
│   │   ├── types.ts           # Zod schema + AppConfig types
│   │   └── loader.ts          # YAML loader (singleton, validated on startup)
│   ├── middleware/
│   │   ├── auth.ts            # API key auth + dev localhost bypass
│   │   ├── rateLimiter.ts     # express-rate-limit factories (global + session-create)
│   │   ├── errorHandler.ts    # Global Express error handler
│   │   └── errors.ts          # Typed error classes (AppError, NotFoundError, …)
│   ├── openapi/
│   │   └── spec.ts            # OpenAPI 3.0 document
│   ├── routes/
│   │   ├── sessions.ts        # POST/GET/DELETE /sessions
│   │   └── chat.ts            # POST /sessions/:id/messages
│   ├── services/
│   │   ├── stores/
│   │   │   ├── ISessionStore.ts       # Store interface
│   │   │   ├── RedisSessionStore.ts   # Redis implementation (stage/prod)
│   │   │   └── InMemorySessionStore.ts # Map + setTimeout TTL (dev)
│   │   ├── sessionStoreFactory.ts     # Returns correct store by mode
│   │   ├── sessionService.ts          # Thin delegation layer used by routes
│   │   ├── azureService.ts            # AgentsClient: initAgent, createThread, sendMessage, deleteThread
│   │   ├── redisService.ts            # ioredis connection factory
│   │   └── logger.ts                  # Winston logger (mode-aware level + format)
│   ├── types/
│   │   └── index.ts           # Session, Message, SessionSummary types
│   ├── ui/
│   │   └── dist/              # Built React UI (generated by npm run build:ui)
│   ├── app.ts                 # Express app (middleware + routes)
│   └── server.ts              # Entry point (load config, connect Redis, listen)
├── ui/                        # Vite + React + Tailwind source
│   └── src/
│       ├── api/client.ts      # Typed API client
│       ├── components/        # SessionList, ChatPanel, MessageBubble
│       └── App.tsx
├── config.example.yaml        # Safe config template (committed)
├── config.yaml                # Your local config (gitignored)
└── package.json
```

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## User Interfaces

**Sections:** [API Explorer](#api-explorer--httplocalhost3000api-docs) · [Chat Test UI](#chat-test-ui--httplocalhost3000chat)

Two browser UIs ship with the server — no separate deployment needed.

### API Explorer — `http://localhost:3000/api-docs`

Interactive Swagger UI backed by an OpenAPI 3.0 spec. Every endpoint is documented with request/response schemas and inline examples.

- Click **Authorize** (top-right) and enter your `X-API-Key` to enable authenticated requests
- Use **Try it out** on any endpoint to execute real requests against the running server
- In `dev` mode, the key field can be left blank — localhost requests are auto-authenticated

### Chat Test UI — `http://localhost:3000/chat`

A React app for end-to-end multi-turn chat testing.

- **Left panel:** all active sessions with client name, short UUID, message count, last-active time, and status badge. **New Session** and **Delete** buttons. On page load the UI fetches existing sessions and populates the list.
- **Right panel:** conversation thread — user messages on the right (indigo), assistant replies on the left (white). Animated typing indicator, auto-scroll, Enter-to-send, Shift+Enter for newlines.
- **API key:** enter in the masked field in the top bar. Leave blank in `dev` mode on localhost.
- **Backend down:** amber warning banner appears when the backend is unreachable; auto-retries every 5 seconds.

> **Rebuild after source changes:** `npm run build:ui`

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## API Reference

**Endpoints:** [`GET /health`](#get-health) · [`POST /generate`](#post-generate) · [`POST /search`](#post-search) · [`POST /sessions`](#post-sessions) · [`GET /sessions`](#get-sessions) · [`GET /sessions/:id`](#get-sessionsid) · [`DELETE /sessions/:id`](#delete-sessionsid) · [`POST /sessions/:id/messages`](#post-sessionsidmessages)

All `/sessions` and `/generate` and `/search` endpoints require the `X-API-Key` header (except in `dev` mode on localhost).

### Endpoints overview

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | None | Server health check |
| `POST` | `/generate` | ✅ | Single-turn AI response (no session needed) |
| `POST` | `/search` | ✅ | Search regulations or cases index |
| `POST` | `/sessions` | ✅ | Create a new chat session |
| `GET` | `/sessions` | ✅ | List all sessions with metadata |
| `GET` | `/sessions/:id` | ✅ | Get session details + recent messages |
| `DELETE` | `/sessions/:id` | ✅ | Terminate a session immediately |
| `POST` | `/sessions/:id/messages` | ✅ | Send a message and receive an AI reply |

---

### `GET /health`

No authentication required.

```
GET /health
```

**Response `200`**
```json
{ "status": "ok", "timestamp": "2024-05-01T10:00:00.000Z" }
```

---

### `POST /generate`

Sends a single prompt to the **Azure OpenAI Responses API** and returns one AI reply. No session or conversation history is involved — each call is fully independent. Uses the `azure.systemPrompt` from config as the model instructions.

**When to use this vs `/sessions/:id/messages`:**

| | `POST /generate` | `POST /sessions/:id/messages` |
|-|-----------------|-------------------------------|
| History / context | ❌ Stateless, no memory | ✅ Full thread history via Azure |
| Session required | ❌ No | ✅ Yes — create with `POST /sessions` first |
| Use case | One-off queries, quick lookups | Multi-turn conversations |

**Headers**
```
X-API-Key: <key>
Content-Type: application/json
```

**Request body**
```json
{ "userInput": "I want legal advice" }
```

| Field | Type | Constraints |
|-------|------|-------------|
| `userInput` | string | 1 – `safeguards.maxMessageChars` characters (default **4 000**) |

**Response `200`**
```json
{
  "reply": "Here are some general legal considerations you should be aware of...",
  "model": "gpt-4o",
  "usage": {
    "inputTokens": 14,
    "outputTokens": 210,
    "totalTokens": 224
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `reply` | string | The AI-generated response text |
| `model` | string | The model deployment name that produced the response |
| `usage.inputTokens` | number | Tokens consumed by the prompt |
| `usage.outputTokens` | number | Tokens generated in the reply |
| `usage.totalTokens` | number | Total tokens billed for this call |

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `400` | `VALIDATION_ERROR` | `userInput` is missing, empty, or exceeds char limit |
| `400` | `INVALID_JSON` | Request body is not valid JSON |
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `413` | `PAYLOAD_TOO_LARGE` | Request body exceeds `safeguards.requestBodyLimitKb` |
| `429` | `RATE_LIMIT` | Exceeds global rate limit |
| `502` | `UPSTREAM_ERROR` | Azure OpenAI Responses API returned an error |
| `504` | `UPSTREAM_TIMEOUT` | Azure call exceeded `safeguards.azureTimeoutMs` |

---

### `POST /search`

Searches the **Azure AI Search** index for the given mode. Two modes are supported — `regulations` and `cases` — each backed by a separate index configured in `config.yaml`.

Uses **semantic search** when a `semanticConfig` is set for the mode (returns ranked, caption-highlighted results). Falls back to **simple keyword search** otherwise.

After retrieving hits, the top results are sent to **Azure AI Foundry** as grounded context and an AI-synthesized `reply` is generated alongside the raw search results. If Foundry synthesis fails for any reason, the raw search results are still returned with a `synthesisError` field instead.

**Headers**
```
X-API-Key: <key>
Content-Type: application/json
```

**Request body**
```json
{
  "query": "housing regulations tenant rights",
  "mode": "regulations",
  "top": 10,
  "skip": 0
}
```

| Field | Type | Required | Default | Description |
|-------|------|:--------:|---------|-------------|
| `query` | string | ✅ | — | Search query text (max `safeguards.maxMessageChars` chars) |
| `mode` | `"regulations"` \| `"cases"` | ✅ | — | Which index to search |
| `top` | integer 1–50 | No | `10` | Max results to return |
| `skip` | integer ≥ 0 | No | `0` | Results to skip (for pagination) |

**Response `200`**
```json
{
  "mode": "regulations",
  "query": "housing regulations tenant rights",
  "count": 142,
  "top": 10,
  "skip": 0,
  "results": [
    {
      "score": 0.9312,
      "captions": [
        {
          "text": "Tenants have the right to quiet enjoyment of their residence...",
          "highlights": "Tenants have the right to <em>quiet enjoyment</em>..."
        }
      ],
      "document": {
        "id": "reg-001",
        "title": "Residential Tenancies Act",
        "content": "..."
      }
    }
  ],
  "reply": "Based on the search results, tenants have several key rights under housing regulations including...",
  "model": "gpt-5-mini",
  "usage": {
    "inputTokens": 820,
    "outputTokens": 210,
    "totalTokens": 1030
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | Echoes the requested mode |
| `query` | string | Echoes the query |
| `count` | integer \| null | Total matching documents in the index (null if not returned) |
| `top` | integer | Max results requested |
| `skip` | integer | Offset requested |
| `results` | array | Ranked result items |
| `results[].score` | number \| null | Relevance score from Azure AI Search |
| `results[].captions` | array \| undefined | Extractive captions from semantic search — most relevant text excerpts |
| `results[].captions[].text` | string | Plain caption text |
| `results[].captions[].highlights` | string \| undefined | HTML-highlighted version (e.g. `<em>keyword</em>`) |
| `results[].document` | object | Raw document fields from the index |
| `reply` | string \| null | AI-synthesized answer from Azure AI Foundry using the hits as context. `null` if synthesis failed |
| `model` | string \| null | Model deployment that produced the reply |
| `usage` | object \| null | Token usage for the Foundry synthesis call |
| `synthesisError` | string | *(Only present when synthesis failed)* Error message — raw search results are still valid |

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `400` | `VALIDATION_ERROR` | `query` missing/empty, `mode` invalid, or query exceeds char limit |
| `400` | `INVALID_JSON` | Request body is not valid JSON |
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `413` | `PAYLOAD_TOO_LARGE` | Request body exceeds `safeguards.requestBodyLimitKb` |
| `429` | `RATE_LIMIT` | Exceeds global rate limit |
| `502` | `UPSTREAM_ERROR` | Azure AI Search returned an error |
| `503` | `SEARCH_NOT_CONFIGURED` | The requested mode has no config in `config.yaml` |
| `504` | `UPSTREAM_TIMEOUT` | Azure AI Search or Foundry synthesis call exceeded `safeguards.azureTimeoutMs` |

---

### `POST /sessions`

Creates a new chat session and allocates a new Azure AI Foundry thread to hold the conversation.

```
POST /sessions
X-API-Key: <your-key>
```

**Response `201`**
```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "clientName": "client-a",
  "createdAt": "2024-05-01T10:00:00.000Z",
  "status": "active"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sessionId` | UUID v4 string | Use in all subsequent calls |
| `clientName` | string | Name from the matched API key (or `"dev-local"` in dev mode) |
| `createdAt` | ISO 8601 string | Session creation timestamp |
| `status` | `"active"` | Always `"active"` at creation |

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `429` | `RATE_LIMIT` | Exceeds `sessionCreateLimitMax` requests per window |
| `429` | `SESSION_LIMIT` | Caller already has `maxSessionsPerClient` open sessions |
| `429` | `SESSION_LIMIT` | Server-wide `maxTotalSessions` cap reached |

---

### `POST /sessions/:id/messages`

Appends the user message to the Azure thread, runs the agent, and returns the reply. The session TTL is reset on every successful call. Azure manages the full conversation history inside the thread — no history is sent in the request.

```
POST /sessions/:id/messages
X-API-Key: <your-key>
Content-Type: application/json

{ "message": "What is the capital of France?" }
```

**Constraints:** `message` must be 1–`safeguards.maxMessageChars` characters (default **4 000**).

**Response `200`**
```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "reply": "The capital of France is Paris.",
  "messageCount": 2,
  "lastActivityAt": "2024-05-01T10:01:00.000Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sessionId` | UUID v4 string | Echoes the session ID |
| `reply` | string | The assistant's response text |
| `messageCount` | number | Total messages after this turn (increments by 2) |
| `lastActivityAt` | ISO 8601 string | Updated activity timestamp |

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `400` | `VALIDATION_ERROR` | `id` not a valid UUID, message is empty, or message exceeds char limit |
| `400` | `INVALID_JSON` | Request body is not valid JSON |
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `404` | `NOT_FOUND` | Session does not exist or has expired |
| `413` | `PAYLOAD_TOO_LARGE` | Request body exceeds `safeguards.requestBodyLimitKb` |
| `429` | `RATE_LIMIT` | Exceeds global rate limit |
| `502` | `UPSTREAM_ERROR` | Azure AI Foundry returned an error |
| `504` | `UPSTREAM_TIMEOUT` | Azure call exceeded `safeguards.azureTimeoutMs` |

---

### `GET /sessions`

Returns all active sessions sorted by most-recently active, newest first. Expired sessions are removed automatically and will not appear.

```
GET /sessions
X-API-Key: <your-key>
```

**Response `200`**
```json
{
  "sessions": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "clientName": "client-a",
      "createdAt": "2024-05-01T10:00:00.000Z",
      "lastActivityAt": "2024-05-01T10:05:00.000Z",
      "status": "active",
      "messageCount": 4
    }
  ],
  "total": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sessions` | `SessionSummary[]` | Array sorted descending by `lastActivityAt` |
| `total` | number | Length of the `sessions` array |

**`SessionSummary` fields:** `id` (UUID), `clientName`, `createdAt`, `lastActivityAt`, `status` (`"active"`), `messageCount`.

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `429` | `RATE_LIMIT` | Exceeds global rate limit |

---

### `GET /sessions/:id`

Returns session metadata plus the last 10 messages of the conversation.

```
GET /sessions/:id
X-API-Key: <your-key>
```

**Response `200`**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "clientName": "client-a",
  "createdAt": "2024-05-01T10:00:00.000Z",
  "lastActivityAt": "2024-05-01T10:05:00.000Z",
  "status": "active",
  "messageCount": 6,
  "historyLength": 6,
  "recentMessages": [
    { "role": "user",      "content": "What is 2+2?",        "timestamp": "2024-05-01T10:01:00.000Z" },
    { "role": "assistant", "content": "2+2 equals 4.",        "timestamp": "2024-05-01T10:01:01.000Z" },
    { "role": "user",      "content": "Multiply that by 3.",  "timestamp": "2024-05-01T10:02:00.000Z" },
    { "role": "assistant", "content": "4 multiplied by 3 is 12.", "timestamp": "2024-05-01T10:02:01.000Z" }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| All `SessionSummary` fields | — | See `GET /sessions` |
| `historyLength` | number | Total messages stored locally (up to `maxHistoryLength`) |
| `recentMessages` | `Message[]` | Last 10 messages, oldest first. Each has `role` (`"user"` or `"assistant"`), `content`, `timestamp`. |

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `400` | `VALIDATION_ERROR` | `id` is not a valid UUID v4 |
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `404` | `NOT_FOUND` | Session does not exist or has expired |
| `429` | `RATE_LIMIT` | Exceeds global rate limit |

---

### `DELETE /sessions/:id`

Removes the session and deletes the backing Azure AI Foundry thread. Returns no content.

```
DELETE /sessions/:id
X-API-Key: <your-key>
```

**Response `204`** — no body.

**Error responses**

| Status | Code | Condition |
|--------|------|-----------|
| `400` | `VALIDATION_ERROR` | `id` is not a valid UUID v4 |
| `401` | `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| `404` | `NOT_FOUND` | Session does not exist or has already expired |
| `429` | `RATE_LIMIT` | Exceeds global rate limit |

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Error Responses

**Sections:** [Error code reference](#complete-error-code-reference) · [Rate limit headers](#rate-limit-response-headers)

All errors use a consistent envelope:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description",
    "stack": "..."  // only present in dev and stage modes for 5xx errors
  }
}
```

### Complete error code reference

| HTTP | Code | Description |
|------|------|-------------|
| `400` | `VALIDATION_ERROR` | Missing/invalid request body, path param, or message too long |
| `400` | `INVALID_JSON` | Request body is not valid JSON |
| `401` | `UNAUTHORIZED` | Missing `X-API-Key` header or key not recognised |
| `404` | `NOT_FOUND` | Session ID does not exist or has already expired |
| `410` | `SESSION_EXPIRED` | Session TTL elapsed before the request completed |
| `413` | `PAYLOAD_TOO_LARGE` | Request body exceeds `safeguards.requestBodyLimitKb` |
| `429` | `RATE_LIMIT` | IP exceeded global or session-create rate limit |
| `429` | `SESSION_LIMIT` | Per-client or total session cap reached |
| `500` | `INTERNAL_ERROR` | Unexpected server-side error |
| `502` | `UPSTREAM_ERROR` | Azure AI Foundry returned an error |
| `503` | `BACKEND_UNAVAILABLE` | Returned by Vite dev proxy when the backend is not running |
| `504` | `UPSTREAM_TIMEOUT` | Azure call exceeded `safeguards.azureTimeoutMs` |

### Rate limit response headers

Present on all `/sessions` responses:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1714560060
```

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## CORS

**Sections:** [Dev mode](#dev-mode) · [Stage / Prod](#stage--prod)

Cross-Origin Resource Sharing is configured via the `cors:` section in `config.yaml`.

| Config key | Default | Description |
|-----------|---------|-------------|
| `cors.allowedOrigins` | `[]` | List of origins permitted to call the API from a browser |
| `cors.allowCredentials` | `true` | Send `Access-Control-Allow-Credentials: true` (required for `X-API-Key` headers) |

**Allowed methods:** `GET`, `POST`, `DELETE`, `OPTIONS`

**Allowed request headers:** `Content-Type`, `X-API-Key`

### Dev mode

All `localhost` and `127.0.0.1` origins (any port) are automatically allowed — no config needed.

### Stage / Prod

Add every origin your web app may be served from:

```yaml
cors:
  allowedOrigins:
    - "https://myapp.example.com"
    - "https://staging.myapp.example.com"
  allowCredentials: true
```

To allow all origins (e.g. a fully public API):

```yaml
cors:
  allowedOrigins:
    - "*"
  allowCredentials: false   # must be false with wildcard origin
```

> Requests with no `Origin` header (curl, server-to-server, Swagger UI) are always allowed regardless of this setting.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Search Configuration

The search service is configured via the `search:` section in `config.yaml`.

| Config key | Default | Description |
|-----------|---------|-------------|
| `search.dnsSuffix` | `search.windows.net` | DNS suffix for Azure AI Search |
| `search.apiVersion` | `2023-11-01` | Azure AI Search REST API version |
| `search.regulations.service` | — | Search service name for regulations |
| `search.regulations.key` | — | API key for the regulations search service |
| `search.regulations.index` | — | Index name for regulations |
| `search.regulations.semanticConfig` | — | Semantic ranker config name (omit for simple search) |
| `search.cases.*` | — | Same fields for the cases index |

**Search URL pattern:**
```
POST https://<service>.<dnsSuffix>/indexes/<index>/docs/search?api-version=<apiVersion>
```

When `semanticConfig` is set the query uses `queryType: "semantic"` with extractive answers and captions. When omitted it falls back to `queryType: "simple"`.

**Azure AI Search API keys** are used directly (unlike Azure AI Foundry which requires Entra ID). Get your key from:
> Azure Portal → your Azure AI Search resource → Settings → Keys → Primary admin key (or query key)

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Safeguards Reference

| Safeguard | Config key | Default | Triggered response |
|-----------|-----------|---------|-------------------|
| Request body size | `requestBodyLimitKb` | 64 KB | `413 PAYLOAD_TOO_LARGE` |
| Global rate limit | `rateLimitMaxRequests` / `rateLimitWindowMs` | 60 req / 60 s per IP | `429 RATE_LIMIT` |
| Session creation rate | `sessionCreateLimitMax` | 10 creates / 60 s per IP | `429 RATE_LIMIT` |
| Message length | `maxMessageChars` | 4 000 chars | `400 VALIDATION_ERROR` |
| Per-client session cap | `maxSessionsPerClient` | 10 sessions | `429 SESSION_LIMIT` |
| Total session cap | `maxTotalSessions` | 200 sessions | `429 SESSION_LIMIT` |
| Azure call timeout | `azureTimeoutMs` | 30 000 ms | `504 UPSTREAM_TIMEOUT` |

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Session Lifetime

- **`dev` mode:** sessions live in-process memory. A `setTimeout` fires when the TTL elapses and removes the entry automatically. All sessions are lost on server restart.
- **`stage`/`prod` mode:** sessions are stored in Redis with a native `EX` TTL. The TTL is **reset on every message**, so a session only expires after `session.timeoutMinutes` of inactivity.
- Accessing an expired or unknown session returns `404`.
- Use `DELETE /sessions/:id` to end a session before its TTL. This also deletes the backing Azure AI Foundry thread.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Testing with curl

**Sections:** [Dev mode](#dev-mode-localhost--no-api-key-needed) · [Stage / Prod mode](#stage--prod-mode-api-key-required) · [Multi-turn walkthrough](#complete-multi-turn-conversation-walkthrough) · [Error responses](#testing-error-responses)

> **Tip:** pipe responses through `jq` for readable output. If `jq` is not installed: `brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu).

### Dev mode (localhost — no API key needed)

```bash
BASE="http://localhost:3000"

# Health check
curl -s "$BASE/health" | jq .

# Single-turn generate (no session needed)
curl -s -X POST "$BASE/generate" \
  -H "Content-Type: application/json" \
  -d '{"userInput": "I want legal advice"}' | jq .

# Search regulations index
curl -s -X POST "$BASE/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "housing tenant rights eviction", "mode": "regulations"}' | jq .

# Search cases index with pagination
curl -s -X POST "$BASE/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "landlord breach of lease", "mode": "cases", "top": 5, "skip": 0}' | jq .

# Create a session
SESSION=$(curl -s -X POST "$BASE/sessions" | jq -r '.sessionId')
echo "Session: $SESSION"

# Send a message
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the capital of France?"}' | jq .

# Follow-up question (full conversation context is maintained)
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is its population?"}' | jq .

# List all sessions
curl -s "$BASE/sessions" | jq .

# Inspect a specific session (last 10 messages shown)
curl -s "$BASE/sessions/$SESSION" | jq .

# Delete the session
curl -s -X DELETE "$BASE/sessions/$SESSION"
echo "Session deleted (HTTP 204)"
```

---

### Stage / Prod mode (API key required)

```bash
BASE="http://localhost:3000"
KEY="your-secret-key-1"

# Reusable header shorthand (add to every request)
AUTH=(-H "X-API-Key: $KEY")

# Health check (no auth needed)
curl -s "$BASE/health" | jq .

# Create a session
SESSION=$(curl -s -X POST "$BASE/sessions" "${AUTH[@]}" | jq -r '.sessionId')
echo "Session: $SESSION"

# Send a message
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d '{"message": "Explain quantum entanglement in simple terms."}' | jq .

# Continue the conversation
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d '{"message": "Give me a real-world analogy for that."}' | jq .

# List all active sessions
curl -s "$BASE/sessions" "${AUTH[@]}" | jq '.sessions[] | {id, clientName, messageCount, lastActivityAt}'

# Get session detail
curl -s "$BASE/sessions/$SESSION" "${AUTH[@]}" | jq .

# Delete the session
curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/sessions/$SESSION" "${AUTH[@]}"
# → 204
```

---

### Complete multi-turn conversation walkthrough

This example shows how context is preserved across messages within a session.

```bash
BASE="http://localhost:3000"
# Omit -H "X-API-Key: ..." lines if running in dev mode on localhost

# 1. Start a session
SESSION=$(curl -s -X POST "$BASE/sessions" | jq -r '.sessionId')
echo "▶ Session: $SESSION"

# 2. First question
echo "--- Turn 1 ---"
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  -H "Content-Type: application/json" \
  -d '{"message": "My name is Alice. Remember that."}' | jq '{reply, messageCount}'

# 3. Second question — AI should remember the name from turn 1
echo "--- Turn 2 ---"
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is my name?"}' | jq '{reply, messageCount}'

# 4. Third question — continue building on previous answers
echo "--- Turn 3 ---"
curl -s -X POST "$BASE/sessions/$SESSION/messages" \
  -H "Content-Type: application/json" \
  -d '{"message": "Now invent a short story about me."}' | jq '{reply, messageCount}'

# 5. Check the session state
echo "--- Session state ---"
curl -s "$BASE/sessions/$SESSION" | jq '{id, messageCount, historyLength, status}'

# 6. End the session
curl -s -X DELETE "$BASE/sessions/$SESSION"
echo "▶ Session ended"
```

---

### Testing error responses

```bash
BASE="http://localhost:3000"

# 401 — missing API key (stage/prod mode)
curl -s -X POST "$BASE/sessions" | jq .
# {"error":{"code":"UNAUTHORIZED","message":"Missing X-API-Key header"}}

# 401 — wrong API key
curl -s -X POST "$BASE/sessions" -H "X-API-Key: wrong-key" | jq .
# {"error":{"code":"UNAUTHORIZED","message":"Invalid API key"}}

# 404 — session not found
curl -s "$BASE/sessions/00000000-0000-0000-0000-000000000000" | jq .
# {"error":{"code":"NOT_FOUND","message":"Session not found"}}

# 400 — empty message body
curl -s -X POST "$BASE/sessions/00000000-0000-0000-0000-000000000000/messages" \
  -H "Content-Type: application/json" \
  -d '{"message": ""}' | jq .
# {"error":{"code":"VALIDATION_ERROR","message":"message must not be empty"}}

# 400 — invalid UUID format
curl -s "$BASE/sessions/not-a-uuid" | jq .
# {"error":{"code":"VALIDATION_ERROR","message":"Invalid session ID format"}}

# 413 — body too large (exceeds requestBodyLimitKb)
curl -s -X POST "$BASE/sessions" \
  -H "Content-Type: application/json" \
  -d '{"junk":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' | jq .
# (send >64 KB payload) → {"error":{"code":"PAYLOAD_TOO_LARGE","message":"Request body exceeds the allowed size limit."}}
```

> In `dev` and `stage` modes, `500` error responses also include a `stack` field with the full stack trace for easier debugging.

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## npm Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | ts-node-dev hot-reload (backend only, same as `./dev.sh --backend`) |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm start` | Run compiled `dist/server.js` |
| `npm run build:ui` | Build React UI to `src/ui/dist/` |
| `npm run build:all` | Build both backend and UI |
| `npm run dev:all` | Hot-reload backend + Vite HMR UI (same as `./dev.sh`) |
| `npm test` | Run backend tests |
| `npm run test:watch` | Run backend tests in watch mode |
| `npm run test:coverage` | Run backend tests with coverage report |

---


<sub>[↑ Back to Table of Contents](#table-of-contents)</sub>

## Running Tests

**Sections:** [Backend Tests (Jest)](#backend-tests-jest) · [Frontend Tests (Vitest)](#frontend-tests-vitest)

The project includes comprehensive test suites for both backend and frontend with 100% coverage targets.

### Backend Tests (Jest)

The backend uses **Jest** with **ts-jest** for unit and integration testing.

**Run all backend tests:**
```bash
npm test
```

**Run tests in watch mode (auto-rerun on file changes):**
```bash
npm run test:watch
```

**Run tests with coverage report:**
```bash
npm run test:coverage
```

Coverage reports are generated in the `coverage/` directory. Open `coverage/lcov-report/index.html` in a browser to view the detailed HTML report.

**Test coverage includes:**
- Configuration loading (YAML files and environment variables)
- Authentication middleware (dev/stage/prod modes, API keys, localhost bypass)
- Error handling (AppError hierarchy, Express errors, upstream errors)
- Session management (create, read, update, delete, list, expiry)
- Session stores (In-Memory and Redis implementations)
- All API routes with validation, timeouts, and error cases
- Rate limiting

### Frontend Tests (Vitest)

The React UI uses **Vitest** with **React Testing Library** for component testing.

**Run all frontend tests:**
```bash
cd ui
npm test
```

**Run tests with UI (interactive test runner):**
```bash
cd ui
npm run test:ui
```

**Run tests with coverage report:**
```bash
cd ui
npm run test:coverage
```

**Test coverage includes:**
- API client (all CRUD operations, error handling)
- ChatPanel component (message sending, error states, loading indicators)
- MessageBubble component (user/assistant messages, styling, timestamps)
- SessionList component (rendering, selection, deletion, status display)

**Coverage thresholds:**
Both backend and frontend are configured with 100% coverage thresholds for:
- Lines
- Functions
- Branches
- Statements


