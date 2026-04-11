import { AzureOpenAI } from 'openai';
import { getBearerTokenProvider, DefaultAzureCredential } from '@azure/identity';
import { loadConfig } from '../config/loader';
import logger from './logger';
import type { SearchResultItem } from './searchService';

let responsesClient: AzureOpenAI | null = null;

function isVerbose(): boolean {
  const { mode } = loadConfig();
  return mode === 'dev' || mode === 'stage';
}

/**
 * Extracts the resource-level base URL from the Azure AI Foundry project endpoint.
 * projectEndpoint: https://<resource>.services.ai.azure.com/api/projects/<project>
 * baseEndpoint:    https://<resource>.services.ai.azure.com
 */
function getBaseEndpoint(projectEndpoint: string): string {
  const url = new URL(projectEndpoint);
  return `${url.protocol}//${url.host}`;
}

function getClient(): AzureOpenAI {
  if (responsesClient) return responsesClient;

  const { azure } = loadConfig();
  const baseEndpoint = getBaseEndpoint(azure.projectEndpoint);

  // Azure OpenAI Responses API requires Entra ID authentication.
  // getBearerTokenProvider wraps DefaultAzureCredential to supply fresh tokens automatically.
  const credential = new DefaultAzureCredential();
  const azureADTokenProvider = getBearerTokenProvider(
    credential,
    'https://cognitiveservices.azure.com/.default'
  );

  responsesClient = new AzureOpenAI({
    endpoint: baseEndpoint,
    azureADTokenProvider,
    apiVersion: azure.responsesApiVersion,
  });

  logger.debug('Azure OpenAI Responses client initialised', {
    baseEndpoint,
    deployment: azure.deployment,
    apiVersion: azure.responsesApiVersion,
  });

  return responsesClient;
}

/**
 * Extracts structured error information from any thrown Azure/OpenAI SDK error.
 */
function extractError(err: unknown): { status: number | null; message: string; body: unknown } {
  if (err && typeof err === 'object') {
    const e = err as Record<string, unknown>;
    const status = typeof e['status'] === 'number' ? e['status'] : null;
    const message = typeof e['message'] === 'string' ? e['message'] : String(err);
    const body = e['body'] ?? e['error'] ?? e['response'] ?? null;
    return { status, message, body };
  }
  return { status: null, message: String(err), body: null };
}

export interface GenerateResult {
  reply: string;
  model: string;
  usage: {
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
  };
}

/**
 * Extracts a short text snippet from a search result for use in a synthesis prompt.
 * Prefers semantic captions (most relevant excerpt), then common content fields.
 */
function extractResultText(item: SearchResultItem): string {
  if (item.captions && item.captions.length > 0) {
    return item.captions.map((c) => c.text).join(' ').slice(0, 600);
  }
  const doc = item.document as Record<string, unknown>;
  const contentFields = ['content', 'text', 'chunk', 'body', 'description', 'summary', 'excerpt'];
  for (const field of contentFields) {
    if (typeof doc[field] === 'string' && (doc[field] as string).length > 0) {
      return (doc[field] as string).slice(0, 600);
    }
  }
  for (const val of Object.values(doc)) {
    if (typeof val === 'string' && val.length > 20) {
      return val.slice(0, 600);
    }
  }
  return '[No text content available]';
}

/**
 * Synthesizes search results into a coherent AI response using Azure OpenAI Responses API.
 * Formats the top hits as grounded context and asks the model to answer the original query.
 */
export async function synthesizeSearchResults(
  query: string,
  mode: string,
  results: SearchResultItem[],
): Promise<GenerateResult> {
  const snippets = results
    .map((item, i) => `[${i + 1}] ${extractResultText(item)}`)
    .join('\n\n');

  const prompt =
    `Search query: "${query}" (source: ${mode} database)\n\n` +
    `Top ${results.length} search result(s):\n\n${snippets}\n\n` +
    `Based on the above search results, provide a clear and helpful answer to the search query. ` +
    `Reference specific findings where relevant.`;

  return generateResponse(prompt);
}
export async function generateResponse(userInput: string): Promise<GenerateResult> {
  const { azure } = loadConfig();
  const client = getClient();
  const verbose = isVerbose();

  if (verbose) {
    logger.debug('→ Azure OpenAI Responses API request', {
      deployment: azure.deployment,
      apiVersion: azure.responsesApiVersion,
      userInput,
    });
  }

  try {
    const response = await client.responses.create({
      model: azure.deployment,
      input: userInput,
      instructions: azure.systemPrompt,
      max_output_tokens: azure.maxTokens,
    });

    // Extract the text from the first output message's content block
    let reply = '';
    for (const item of response.output) {
      if (item.type === 'message' && item.role === 'assistant') {
        for (const block of item.content) {
          if (block.type === 'output_text' && 'text' in block) {
            reply = (block as { type: 'output_text'; text: string }).text;
            break;
          }
        }
        break;
      }
    }

    if (!reply) {
      throw new Error('Azure OpenAI Responses API returned an empty response');
    }

    const result: GenerateResult = {
      reply,
      model: response.model,
      usage: {
        inputTokens: response.usage?.input_tokens ?? 0,
        outputTokens: response.usage?.output_tokens ?? 0,
        totalTokens: response.usage?.total_tokens ?? 0,
      },
    };

    if (verbose) {
      logger.debug('← Azure OpenAI Responses API response', {
        model: result.model,
        usage: result.usage,
        reply: result.reply,
      });
    }

    return result;
  } catch (err: unknown) {
    const { status, message: rawMessage, body } = extractError(err);

    logger.error('✖ Azure OpenAI Responses API error', {
      status,
      deployment: azure.deployment,
      error: rawMessage,
      azureResponseBody: body,
    });

    if (status !== null) {
      if (status === 404) {
        throw new Error(
          `Azure OpenAI Responses API 404 — deployment not found.\n` +
          `Check azure.deployment in config.yaml: "${azure.deployment}"`
        );
      }
      if (status === 401) {
        throw new Error(`Azure OpenAI Responses API authentication failed (401). Run 'az login' or set service principal env vars.`);
      }
      if (status === 429) {
        throw new Error(`Azure OpenAI Responses API rate limit exceeded (429). Try again shortly.`);
      }
      throw new Error(`Azure OpenAI Responses API error (${status}): ${rawMessage}`);
    }
    throw err;
  }
}
