import { AgentsClient } from '@azure/ai-agents';
import { DefaultAzureCredential } from '@azure/identity';
import { loadConfig } from '../config/loader';
import logger from './logger';

let agentsClient: AgentsClient | null = null;
let agentId: string | null = null;

function isVerbose(): boolean {
  const { mode } = loadConfig();
  return mode === 'dev' || mode === 'stage';
}

function getClient(): AgentsClient {
  if (agentsClient) return agentsClient;

  const { azure } = loadConfig();

  // Azure AI Foundry Agents API requires Entra ID (Azure AD) authentication.
  // DefaultAzureCredential automatically picks up auth from:
  //  • Local dev:       `az login` (Azure CLI)
  //  • CI / hosted:     AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET env vars
  //  • Azure-hosted:    Managed Identity
  const credential = new DefaultAzureCredential();

  agentsClient = new AgentsClient(azure.projectEndpoint, credential);

  logger.debug('Azure AI Foundry Agents client initialised', {
    projectEndpoint: azure.projectEndpoint,
    deployment: azure.deployment,
  });

  return agentsClient;
}

/**
 * Extracts structured error information from any thrown Azure SDK error.
 * The Azure REST SDK wraps HTTP errors with status, message, and sometimes
 * a `details` or `body` property containing the raw JSON from the service.
 */
function extractAzureError(err: unknown): { status: number | null; message: string; body: unknown } {
  if (err && typeof err === 'object') {
    const e = err as Record<string, unknown>;
    const status = typeof e['status'] === 'number' ? e['status'] : null;
    const message = typeof e['message'] === 'string' ? e['message'] : String(err);
    // Try to capture the raw response body for maximum debugging detail
    const body = e['body'] ?? e['details'] ?? e['response'] ?? null;
    return { status, message, body };
  }
  return { status: null, message: String(err), body: null };
}

/**
 * Creates (or reuses) the backing Azure AI Foundry agent.
 * Call once on server startup before accepting traffic.
 */
export async function initAgent(): Promise<void> {
  const { azure } = loadConfig();
  const client = getClient();

  // Check if an agent with this name already exists; reuse if found.
  try {
    const existing = client.listAgents();
    for await (const a of existing) {
      if (a.name === azure.agentName) {
        agentId = a.id;
        logger.info('Azure AI Foundry agent reused', {
          agentId,
          agentName: azure.agentName,
        });
        return;
      }
    }
  } catch (listErr) {
    const { status, message, body } = extractAzureError(listErr);
    logger.error('✖ Azure AI Foundry — failed to list agents (falling through to create)', {
      status,
      error: message,
      azureResponseBody: body,
      projectEndpoint: azure.projectEndpoint,
    });
    // Re-throw so startup fails loudly — listing usually indicates auth/endpoint issues
    throw listErr;
  }

  try {
    const agent = await client.createAgent(azure.deployment, {
      name: azure.agentName,
      instructions: azure.systemPrompt,
      // Note: temperature is NOT passed here — some models (e.g. gpt-5-mini)
      // reject it at the agent level. It can be passed per-run if needed.
    });

    agentId = agent.id;
    logger.info('Azure AI Foundry agent created', {
      agentId,
      agentName: azure.agentName,
      deployment: azure.deployment,
    });
  } catch (createErr) {
    const { status, message, body } = extractAzureError(createErr);
    logger.error('✖ Azure AI Foundry — failed to create agent', {
      status,
      error: message,
      azureResponseBody: body,
      projectEndpoint: azure.projectEndpoint,
      deployment: azure.deployment,
    });
    throw createErr;
  }
}

/** Creates a new Azure thread and returns its ID. */
export async function createThread(): Promise<string> {
  const client = getClient();
  const thread = await client.threads.create();
  logger.debug('Azure thread created', { threadId: thread.id });
  return thread.id;
}

/** Deletes an Azure thread (called when a session is terminated). */
export async function deleteThread(threadId: string): Promise<void> {
  try {
    const client = getClient();
    await client.threads.delete(threadId);
    logger.debug('Azure thread deleted', { threadId });
  } catch (err) {
    const { status, message, body } = extractAzureError(err);
    logger.warn('Could not delete Azure thread (non-fatal)', {
      threadId,
      status,
      error: message,
      azureResponseBody: body,
    });
  }
}

/**
 * Posts a user message to the thread, runs the agent, and returns the reply.
 * Azure maintains the full conversation history inside the thread.
 */
export async function sendMessage(threadId: string, userMessage: string): Promise<string> {
  if (!agentId) {
    throw new Error('Azure AI Foundry agent is not initialised. Call initAgent() on startup.');
  }

  const { azure } = loadConfig();
  const client = getClient();
  const verbose = isVerbose();

  if (verbose) {
    logger.debug('→ Azure AI Foundry Agents request', {
      threadId,
      agentId,
      deployment: azure.deployment,
      userMessage,
    });
  }

  try {
    // Post the user message to the thread
    await client.messages.create(threadId, 'user', userMessage);

    // Create a run and poll until it completes (blocked until done)
    const run = await client.runs.createAndPoll(threadId, agentId);

    if (run.status !== 'completed') {
      throw new Error(`Azure run ended with status "${run.status}". Check agent configuration.`);
    }

    // Retrieve the most recent assistant message
    let reply: string | null = null;
    const allMessages = client.messages.list(threadId, { order: 'desc' });
    for await (const msg of allMessages) {
      if (msg.role === 'assistant') {
        // Content may be an array of blocks; extract the first text block
        const content = msg.content;
        if (Array.isArray(content)) {
          for (const block of content) {
            if (block.type === 'text' && 'text' in block) {
              reply = (block as { type: 'text'; text: { value: string } }).text.value;
              break;
            }
          }
        } else if (typeof content === 'string') {
          reply = content;
        }
        break;
      }
    }

    if (!reply) {
      throw new Error('Azure AI Foundry returned an empty response');
    }

    if (verbose) {
      logger.debug('← Azure AI Foundry Agents response', {
        threadId,
        runId: run.id,
        runStatus: run.status,
        reply,
      });
    }

    return reply;
  } catch (err: unknown) {
    const { status, message: rawMessage, body } = extractAzureError(err);

    logger.error('✖ Azure AI Foundry Agents error', {
      status,
      threadId,
      agentId,
      deployment: azure.deployment,
      projectEndpoint: azure.projectEndpoint,
      error: rawMessage,
      azureResponseBody: body,
    });

    if (status !== null) {
      if (status === 404) {
        throw new Error(
          `Azure AI Foundry Agents error 404 — resource not found.\n` +
          `Check in config.yaml:\n` +
          `  • azure.projectEndpoint must be in the format:\n` +
          `    https://<AIFoundryResourceName>.services.ai.azure.com/api/projects/<ProjectName>\n` +
          `  • azure.deployment must match the exact model deployment name in the project\n` +
          `Current values: projectEndpoint="${azure.projectEndpoint}", deployment="${azure.deployment}"`
        );
      }
      if (status === 401) {
        throw new Error(
          `Azure AI Foundry authentication failed (401). ` +
          `Verify azure.apiKey in config.yaml — use the key from AI Foundry → project → Settings → Keys.`
        );
      }
      if (status === 429) {
        throw new Error(
          `Azure AI Foundry rate limit exceeded (429). Try again shortly or increase quota in Azure.`
        );
      }
      throw new Error(`Azure AI Foundry Agents error (${status}): ${rawMessage}`);
    }
    throw err;
  }
}

