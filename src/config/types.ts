import { z } from 'zod';

export const APP_MODES = ['dev', 'stage', 'prod'] as const;
export type AppMode = (typeof APP_MODES)[number];

const ApiKeySchema = z.object({
  name: z.string().min(1),
  key: z.string().min(1),
});

const ServerConfigSchema = z.object({
  port: z.number().int().positive().default(3000),
  host: z.string().default('0.0.0.0'),
});

const AuthConfigSchema = z.object({
  apiKeys: z.array(ApiKeySchema).min(1),
});

const AzureConfigSchema = z.object({
  // Full project endpoint from Azure AI Foundry portal → Overview → Libraries → Foundry.
  // Format: https://<AIFoundryResourceName>.services.ai.azure.com/api/projects/<ProjectName>
  projectEndpoint: z.string().url(),

  // Model deployment name — find it under Models + endpoints → your deployment → Name.
  deployment: z.string().min(1),

  // Display name for the agent that will be created/reused in Azure AI Foundry.
  agentName: z.string().default('chat-backend-agent'),

  // System instructions for the agent.
  systemPrompt: z.string().default('You are a helpful assistant.'),

  // Sampling temperature: 0 = deterministic, 1 = balanced, 2 = very creative.
  temperature: z.number().min(0).max(2).default(0.7),

  // Max tokens the agent may generate per turn.
  maxTokens: z.number().int().positive().default(2048),

  // API version for the Azure OpenAI Responses API used by the /generate endpoint.
  responsesApiVersion: z.string().default('2025-03-01-preview'),
});

const RedisConfigSchema = z.object({
  host: z.string().default('localhost'),
  port: z.number().int().positive().default(6379),
  password: z.string().optional(),
  db: z.number().int().min(0).default(0),
});

const SessionConfigSchema = z.object({
  timeoutMinutes: z.number().int().positive().default(30),
  maxHistoryLength: z.number().int().positive().default(100),
});

const SafeguardsConfigSchema = z.object({
  // Max request body size accepted by Express (in kilobytes).
  requestBodyLimitKb: z.number().int().positive().default(64),

  // Global rate limit: max requests per IP per window.
  rateLimitWindowMs: z.number().int().positive().default(60_000),  // 1 minute
  rateLimitMaxRequests: z.number().int().positive().default(60),   // 60 req/min

  // Stricter limit for session creation (POST /sessions).
  sessionCreateLimitMax: z.number().int().positive().default(10),  // 10 new sessions/min

  // Max characters allowed in a single user message.
  maxMessageChars: z.number().int().positive().default(4000),

  // Max concurrent active sessions allowed per API key / client name.
  maxSessionsPerClient: z.number().int().positive().default(10),

  // Hard cap on total concurrent sessions across all clients.
  maxTotalSessions: z.number().int().positive().default(200),

  // Milliseconds before an Azure AI Foundry call is aborted.
  azureTimeoutMs: z.number().int().positive().default(30_000),
});

const CorsConfigSchema = z.object({
  // List of allowed origins. Use ["*"] to allow all origins (not recommended for production).
  // Example: ["https://myapp.com", "http://localhost:8000"]
  // In dev mode, localhost origins are always allowed regardless of this list.
  allowedOrigins: z.array(z.string()).default([]),

  // Allow credentials (cookies, Authorization headers) to be sent cross-origin.
  // Must be false when allowedOrigins contains "*".
  allowCredentials: z.boolean().default(true),
});

const SearchIndexConfigSchema = z.object({
  // Azure AI Search service name (e.g. "search-law-2" → search-law-2.search.windows.net)
  service: z.string().min(1),

  // Admin or query API key for the search service.
  key: z.string().min(1),

  // Name of the index to search.
  index: z.string().min(1),

  // Semantic ranker configuration name. When set, queryType is "semantic".
  // When omitted, queryType falls back to "simple".
  semanticConfig: z.string().optional(),
});

const SearchConfigSchema = z.object({
  // DNS suffix for Azure AI Search (default: search.windows.net)
  dnsSuffix: z.string().default('search.windows.net'),

  // Azure AI Search REST API version.
  apiVersion: z.string().default('2023-11-01'),

  // Regulations index configuration.
  regulations: SearchIndexConfigSchema.optional(),

  // Cases index configuration.
  cases: SearchIndexConfigSchema.optional(),
});

export const AppConfigSchema = z.object({
  mode: z.enum(APP_MODES).default('dev'),
  server: ServerConfigSchema.default({}),
  auth: AuthConfigSchema,
  azure: AzureConfigSchema,
  redis: RedisConfigSchema.default({}),
  session: SessionConfigSchema.default({}),
  safeguards: SafeguardsConfigSchema.default({}),
  cors: CorsConfigSchema.default({}),
  search: SearchConfigSchema.default({}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
export type ApiKeyConfig = z.infer<typeof ApiKeySchema>;
export type AzureConfig = z.infer<typeof AzureConfigSchema>;
export type RedisConfig = z.infer<typeof RedisConfigSchema>;
export type SessionConfig = z.infer<typeof SessionConfigSchema>;
export type SafeguardsConfig = z.infer<typeof SafeguardsConfigSchema>;
export type CorsConfig = z.infer<typeof CorsConfigSchema>;
export type SearchConfig = z.infer<typeof SearchConfigSchema>;
export type SearchIndexConfig = z.infer<typeof SearchIndexConfigSchema>;
