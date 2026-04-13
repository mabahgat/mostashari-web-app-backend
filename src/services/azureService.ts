import { AzureOpenAI } from 'openai';
import { getBearerTokenProvider, DefaultAzureCredential } from '@azure/identity';
import { loadConfig } from '../config/loader';
import logger from './logger';

let openaiClient: AzureOpenAI | null = null;
let agentId: string | null = null;

function isVerbose(): boolean {
  const { mode } = loadConfig();
  return mode === 'dev' || mode === 'stage';
}

/**
 * Derives the Azure OpenAI endpoint (openai.azure.com) from the AI Foundry project endpoint.
 * The Azure OpenAI Assistants API uses cognitiveservices.azure.com audience which works
 * correctly with managed identity — unlike the AI Foundry Agents API (/api/projects/)
 * which only accepts user tokens at the ai.azure.com audience.
 *
 * e.g. https://az-openai-law-1.services.ai.azure.com/api/projects/az-openai-law-1-project
 *   →  https://az-openai-law-1.openai.azure.com
 */
function getOpenAIEndpoint(projectEndpoint: string): string {
  const url = new URL(projectEndpoint);
  const hostname = url.hostname.replace('.services.ai.azure.com', '.openai.azure.com');
  return `${url.protocol}//${hostname}`;
}

function getClient(): AzureOpenAI {
  if (openaiClient) return openaiClient;

  const { azure } = loadConfig();
  const openaiEndpoint = getOpenAIEndpoint(azure.projectEndpoint);

  // Use cognitiveservices.azure.com scope (not ai.azure.com) — this scope works
  // correctly with managed identity on the openai.azure.com endpoint.
  const credential = new DefaultAzureCredential();
  const azureADTokenProvider = getBearerTokenProvider(
    credential,
    'https://cognitiveservices.azure.com/.default',
  );

  openaiClient = new AzureOpenAI({
    endpoint: openaiEndpoint,
    azureADTokenProvider,
    apiVersion: '2024-05-01-preview',
  });

  logger.debug('Azure OpenAI Assistants client initialised', {
    openaiEndpoint,
    deployment: azure.deployment,
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

/** Returns true if the Azure AI Foundry agent is ready to handle requests. */
export function isAgentReady(): boolean {
  return agentId !== null;
}

/**
 * Creates (or reuses) the backing Azure OpenAI assistant.
 * Uses the openai.azure.com endpoint with cognitiveservices.azure.com scope,
 * which is fully compatible with managed identity.
 */
export async function initAgent(): Promise<void> {
  const { azure } = loadConfig();
  const client = getClient();

  // Check if an assistant with this name already exists; reuse if found.
  try {
    const existing = await client.beta.assistants.list({ limit: 100 });
    for (const a of existing.data) {
      if (a.name === azure.agentName) {
        agentId = a.id;
        logger.info('Azure OpenAI assistant reused', {
          agentId,
          agentName: azure.agentName,
        });
        return;
      }
    }
  } catch (listErr) {
    const { status, message, body } = extractError(listErr);
    logger.error('✖ Azure OpenAI — failed to list assistants', {
      status,
      error: message,
      body,
    });
    throw listErr;
  }

  try {
    const agent = await client.beta.assistants.create({
      model: azure.deployment,
      name: azure.agentName,
      instructions: azure.systemPrompt,
    });

    agentId = agent.id;
    logger.info('Azure OpenAI assistant created', {
      agentId,
      agentName: azure.agentName,
      deployment: azure.deployment,
    });
  } catch (createErr) {
    const { status, message, body } = extractError(createErr);
    logger.error('✖ Azure OpenAI — failed to create assistant', {
      status,
      error: message,
      body,
      deployment: azure.deployment,
    });
    throw createErr;
  }
}

/** Creates a new OpenAI thread and returns its ID. */
export async function createThread(): Promise<string> {
  const client = getClient();
  const thread = await client.beta.threads.create();
  logger.debug('Azure thread created', { threadId: thread.id });
  return thread.id;
}

/** Deletes an OpenAI thread (called when a session is terminated). */
export async function deleteThread(threadId: string): Promise<void> {
  try {
    const client = getClient();
    await client.beta.threads.del(threadId);
    logger.debug('Azure thread deleted', { threadId });
  } catch (err) {
    const { status, message, body } = extractError(err);
    logger.warn('Could not delete Azure thread (non-fatal)', {
      threadId,
      status,
      error: message,
      body,
    });
  }
}

/**
 * Posts a user message to the thread, runs the assistant, and returns the reply.
 * OpenAI maintains the full conversation history inside the thread.
 */
export async function sendMessage(threadId: string, userMessage: string): Promise<string> {
  if (!agentId) {
    throw new Error('Azure OpenAI assistant is not initialised. Call initAgent() on startup.');
  }

  const { azure } = loadConfig();
  const client = getClient();
  const verbose = isVerbose();

  if (verbose) {
    logger.debug('→ Azure OpenAI Assistants request', {
      threadId,
      agentId,
      deployment: azure.deployment,
      userMessage,
    });
  }

  try {
    await client.beta.threads.messages.create(threadId, {
      role: 'user',
      content: userMessage,
    });

    const run = await client.beta.threads.runs.createAndPoll(threadId, {
      assistant_id: agentId,
    });

    if (run.status !== 'completed') {
      throw new Error(`Azure run ended with status "${run.status}". Check assistant configuration.`);
    }

    let reply: string | null = null;
    const allMessages = await client.beta.threads.messages.list(threadId, { order: 'desc' });
    for (const msg of allMessages.data) {
      if (msg.role === 'assistant') {
        for (const block of msg.content) {
          if (block.type === 'text') {
            reply = block.text.value;
            break;
          }
        }
        break;
      }
    }

    if (!reply) {
      throw new Error('Azure OpenAI assistant returned an empty response');
    }

    if (verbose) {
      logger.debug('← Azure OpenAI Assistants response', {
        threadId,
        runId: run.id,
        runStatus: run.status,
        reply,
      });
    }

    return reply;
  } catch (err: unknown) {
    const { status, message: rawMessage, body } = extractError(err);

    logger.error('✖ Azure OpenAI Assistants error', {
      status,
      threadId,
      agentId,
      deployment: azure.deployment,
      error: rawMessage,
      body,
    });

    if (status !== null) {
      if (status === 404) {
        throw new Error(
          `Azure OpenAI Assistants error 404 — resource not found.\n` +
          `Check azure.projectEndpoint and azure.deployment in config.`
        );
      }
      if (status === 401) {
        throw new Error(
          `Azure OpenAI authentication failed (401). ` +
          `Verify managed identity has 'Cognitive Services OpenAI User' role on the AI resource.`
        );
      }
      if (status === 429) {
        throw new Error(
          `Azure OpenAI rate limit exceeded (429). Try again shortly or increase quota.`
        );
      }
      throw new Error(`Azure OpenAI Assistants error (${status}): ${rawMessage}`);
    }
    throw err;
  }
}

