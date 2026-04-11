import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { AppConfig, AppConfigSchema } from './types';

let configInstance: AppConfig | null = null;

/**
 * Builds a raw config object from environment variables.
 * Used as a fallback when config.yaml is not present (e.g. CI / Azure App Service).
 *
 * Required env vars: BACKEND_API_KEY, AZURE_PROJECT_ENDPOINT, AZURE_PROJECT_NAME,
 *                    AZURE_DEPLOYMENT, AZURE_AGENT_NAME
 */
function buildConfigFromEnv(): unknown {
  const env = process.env;

  const corsOrigins = (env.CORS_ORIGIN ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  // Combine endpoint + project name into full Foundry project URL
  const projectEndpoint = env.AZURE_PROJECT_ENDPOINT && env.AZURE_PROJECT_NAME
    ? `${env.AZURE_PROJECT_ENDPOINT.replace(/\/+$/, '')}/api/projects/${env.AZURE_PROJECT_NAME}`
    : env.AZURE_PROJECT_ENDPOINT ?? '';

  const regulationsConfigured =
    env.REG_SEARCH_SERVICE && env.REG_SEARCH_KEY && env.REG_SEARCH_INDEX;
  const casesConfigured =
    env.CASES_SEARCH_SERVICE && env.CASES_SEARCH_KEY && env.CASES_SEARCH_INDEX;

  return {
    mode: env.APP_MODE ?? 'prod',
    server: {
      port: env.PORT ? parseInt(env.PORT, 10) : 8080,
      host: env.SERVER_HOST ?? '0.0.0.0',
    },
    auth: {
      apiKeys: [{ name: 'default', key: env.BACKEND_API_KEY ?? '' }],
    },
    azure: {
      projectEndpoint,
      deployment: env.AZURE_DEPLOYMENT ?? '',
      agentName: env.AZURE_AGENT_NAME ?? 'chat-backend-agent',
      systemPrompt: env.SYSTEM_PROMPT ?? 'You are a helpful assistant.',
      temperature: env.AZURE_TEMPERATURE ? parseFloat(env.AZURE_TEMPERATURE) : 0.7,
      maxTokens: env.AZURE_MAX_TOKENS ? parseInt(env.AZURE_MAX_TOKENS, 10) : 2048,
      responsesApiVersion: env.AZURE_RESPONSES_API_VERSION ?? '2025-03-01-preview',
    },
    redis: {
      host: env.REDIS_HOST ?? 'localhost',
      port: env.REDIS_PORT ? parseInt(env.REDIS_PORT, 10) : 6379,
      password: env.REDIS_PASSWORD ?? '',
      db: env.REDIS_DB ? parseInt(env.REDIS_DB, 10) : 0,
    },
    session: {
      timeoutMinutes: env.SESSION_TIMEOUT_MINUTES
        ? parseInt(env.SESSION_TIMEOUT_MINUTES, 10)
        : 30,
      maxHistoryLength: env.SESSION_MAX_HISTORY
        ? parseInt(env.SESSION_MAX_HISTORY, 10)
        : 100,
    },
    safeguards: {
      requestBodyLimitKb: env.REQUEST_BODY_LIMIT_KB
        ? parseInt(env.REQUEST_BODY_LIMIT_KB, 10)
        : 64,
      rateLimitWindowMs: env.RATE_LIMIT_WINDOW
        ? parseInt(env.RATE_LIMIT_WINDOW, 10)
        : 60_000,
      rateLimitMaxRequests: env.RATE_LIMIT_MAX
        ? parseInt(env.RATE_LIMIT_MAX, 10)
        : 60,
      sessionCreateLimitMax: env.SESSION_CREATE_LIMIT_MAX
        ? parseInt(env.SESSION_CREATE_LIMIT_MAX, 10)
        : 10,
      maxMessageChars: env.MAX_MESSAGE_CHARS
        ? parseInt(env.MAX_MESSAGE_CHARS, 10)
        : 4000,
      maxSessionsPerClient: env.MAX_SESSIONS_PER_CLIENT
        ? parseInt(env.MAX_SESSIONS_PER_CLIENT, 10)
        : 10,
      maxTotalSessions: env.MAX_TOTAL_SESSIONS
        ? parseInt(env.MAX_TOTAL_SESSIONS, 10)
        : 200,
      azureTimeoutMs: env.AZURE_TIMEOUT_MS
        ? parseInt(env.AZURE_TIMEOUT_MS, 10)
        : 30_000,
    },
    cors: {
      allowedOrigins: corsOrigins,
      allowCredentials: env.CORS_ALLOW_CREDENTIALS !== 'false',
    },
    search: {
      dnsSuffix: env.SEARCH_DNS_SUFFIX ?? 'search.windows.net',
      apiVersion: env.SEARCH_API_VERSION ?? '2023-11-01',
      ...(regulationsConfigured && {
        regulations: {
          service: env.REG_SEARCH_SERVICE!,
          key: env.REG_SEARCH_KEY!,
          index: env.REG_SEARCH_INDEX!,
          semanticConfig: env.REG_SEMANTIC_CONFIG || undefined,
        },
      }),
      ...(casesConfigured && {
        cases: {
          service: env.CASES_SEARCH_SERVICE!,
          key: env.CASES_SEARCH_KEY!,
          index: env.CASES_SEARCH_INDEX!,
          semanticConfig: env.CASES_SEMANTIC_CONFIG || undefined,
        },
      }),
    },
  };
}

export function loadConfig(): AppConfig {
  if (configInstance) {
    return configInstance;
  }

  const configPath = process.env.CONFIG_PATH ?? path.resolve(process.cwd(), 'config.yaml');
  const useEnvFallback = !fs.existsSync(configPath);

  let raw: unknown;
  if (useEnvFallback) {
    raw = buildConfigFromEnv();
  } else {
    const fileContents = fs.readFileSync(configPath, 'utf-8');
    raw = yaml.load(fileContents);
  }

  const result = AppConfigSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    const source = useEnvFallback ? 'environment variables' : configPath;
    throw new Error(`Invalid configuration (from ${source}):\n${issues}`);
  }

  configInstance = result.data;
  return configInstance;
}

/** Reset singleton — used in tests only. */
export function _resetConfig(): void {
  configInstance = null;
}
