import OpenAI from 'openai';
import { DefaultAzureCredential, getBearerTokenProvider } from '@azure/identity';
import { loadConfig } from '../config/loader';
import logger from './logger';

let openaiClient: OpenAI | null = null;
let tokenProvider: (() => Promise<string>) | null = null;

function isVerbose(): boolean {
  const { mode } = loadConfig();
  return mode === 'dev' || mode === 'stage';
}

function getOpenAIClient(): OpenAI {
  if (openaiClient) return openaiClient;

  const { azure } = loadConfig();
  const credential = new DefaultAzureCredential();

  // The AI Foundry conversations/responses API uses path-based versioning (/openai/v1/...)
  // not query-param versioning, so we use the plain OpenAI client with a baseURL
  // and inject the bearer token on each request via a custom fetch wrapper.
  tokenProvider = getBearerTokenProvider(credential, 'https://ai.azure.com/.default');

  const baseURL = `${azure.projectEndpoint.replace(/\/$/, '')}/openai/v1`;

  openaiClient = new OpenAI({
    baseURL,
    apiKey: 'unused', // required by the SDK but auth is done via the bearer token below
    fetch: async (url, init) => {
      const token = await tokenProvider!();
      const headers = new Headers(init?.headers);
      headers.set('Authorization', `Bearer ${token}`);
      return fetch(url, { ...init, headers });
    },
  });

  logger.debug('Azure AI Foundry client initialised', {
    baseURL,
    agentName: azure.agentName,
    ...(azure.agentVersion ? { agentVersion: azure.agentVersion } : { agentVersion: 'latest' }),
  });

  return openaiClient;
}

/**
 * Extracts structured error information from any thrown OpenAI SDK error.
 */
function extractError(err: unknown): { status: number | null; message: string; body: unknown } {
  if (err && typeof err === 'object') {
    const e = err as Record<string, unknown>;
    const status = typeof e['status'] === 'number' ? e['status'] : null;
    const message = typeof e['message'] === 'string' ? e['message'] : String(err);
    const body = e['error'] ?? e['body'] ?? e['response'] ?? null;
    return { status, message, body };
  }
  return { status: null, message: String(err), body: null };
}

/** Returns true if the Azure AI Foundry agent configuration is ready. */
export function isAgentReady(): boolean {
  // Agent is always ready since we're referencing an existing agent
  return true;
}

/**
 * No initialization needed — we reference an existing agent by name and version.
 * This function is kept for backward compatibility but does nothing.
 */
export async function initAgent(): Promise<void> {
  const { azure } = loadConfig();
  logger.info('Using existing Azure AI agent', {
    agentName: azure.agentName,
    agentVersion: azure.agentVersion ?? 'latest',
  });
}

/** Creates a new conversation and returns its ID. */
export async function createThread(): Promise<string> {
  const openai = getOpenAIClient();
  const conversation = await openai.conversations.create();
  logger.debug('Azure conversation created', { conversationId: conversation.id });
  return conversation.id;
}

/** Deletes a conversation (called when a session is terminated). */
export async function deleteThread(threadId: string): Promise<void> {
  try {
    const openai = getOpenAIClient();
    await openai.conversations.delete(threadId);
    logger.debug('Azure conversation deleted', { conversationId: threadId });
  } catch (err) {
    const { status, message, body } = extractError(err);
    logger.warn('Could not delete Azure conversation (non-fatal)', {
      conversationId: threadId,
      status,
      error: message,
      body,
    });
  }
}

/**
 * Posts a user message to the conversation, generates a response using the referenced agent,
 * and returns the reply. Azure AI maintains the full conversation history.
 */
export async function sendMessage(conversationId: string, userMessage: string): Promise<string> {
  const { azure } = loadConfig();
  const openai = getOpenAIClient();
  const verbose = isVerbose();

  if (verbose) {
    logger.debug('→ Azure AI agent request', {
      conversationId,
      agentName: azure.agentName,
      agentVersion: azure.agentVersion ?? 'latest',
      userMessage,
    });
  }

  try {
    // Generate response using the agent reference
    // Note: The conversation API may handle messages differently than expected.
    // For now, we'll try creating a response directly and see if there's additional
    // configuration needed in the body or options.
    const response = await openai.responses.create(
      { conversation: conversationId },
      {
        body: {
          agent_reference: {
            name: azure.agentName,
            ...(azure.agentVersion ? { version: azure.agentVersion } : {}),
            type: 'agent_reference',
          },
          input: userMessage,
        },
      },
    );

    const reply = response.output_text;

    if (!reply) {
      throw new Error('Azure AI agent returned an empty response');
    }

    if (verbose) {
      const resolved = (response as unknown as Record<string, unknown>)['agent_reference'] as Record<string, unknown> | undefined;
      logger.debug('← Azure AI agent response', {
        conversationId,
        responseId: response.id,
        resolvedAgentVersion: resolved?.['version'] ?? 'unknown',
        reply,
      });
    }

    return reply;
  } catch (err: unknown) {
    const { status, message: rawMessage, body } = extractError(err);

    logger.error('✖ Azure AI agent error', {
      status,
      conversationId,
      agentName: azure.agentName,
      agentVersion: azure.agentVersion ?? 'latest',
      error: rawMessage,
      body,
    });

    if (status !== null) {
      if (status === 404) {
        throw new Error(
          `Azure AI agent error 404 — resource not found.\n` +
          `Check azure.projectEndpoint and azure.agentName in config.`
        );
      }
      if (status === 401) {
        throw new Error(
          `Azure AI authentication failed (401). ` +
          `Verify managed identity has appropriate roles on the AI resource.`
        );
      }
      if (status === 429) {
        throw new Error(
          `Azure AI rate limit exceeded (429). Try again shortly or increase quota.`
        );
      }
      throw new Error(`Azure AI agent error (${status}): ${rawMessage}`);
    }
    throw err;
  }
}

