import { OpenAPIV3 } from 'openapi-types';

const spec: OpenAPIV3.Document = {
  openapi: '3.0.3',
  info: {
    title: 'Chat Backend API',
    version: '1.0.0',
    description:
      'REST API for multi-turn chat sessions forwarded to Azure AI Foundry. ' +
      'All `/sessions` endpoints require the `X-API-Key` header.',
  },
  servers: [{ url: '/', description: 'Current server' }],
  security: [{ ApiKeyAuth: [] }],
  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'Named API key configured in config.yaml under auth.apiKeys',
      },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: {
          error: {
            type: 'object',
            properties: {
              code: { type: 'string', example: 'NOT_FOUND' },
              message: { type: 'string', example: 'Session not found' },
              stack: { type: 'string', description: 'Only present in dev/stage modes' },
            },
            required: ['code', 'message'],
          },
        },
      },
      SessionCreated: {
        type: 'object',
        properties: {
          sessionId: { type: 'string', format: 'uuid', example: '550e8400-e29b-41d4-a716-446655440000' },
          clientName: { type: 'string', example: 'client-a' },
          createdAt: { type: 'string', format: 'date-time' },
          status: { type: 'string', enum: ['active', 'expired'] },
        },
      },
      SessionSummary: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          clientName: { type: 'string' },
          createdAt: { type: 'string', format: 'date-time' },
          lastActivityAt: { type: 'string', format: 'date-time' },
          status: { type: 'string', enum: ['active', 'expired'] },
          messageCount: { type: 'integer', minimum: 0 },
        },
      },
      SessionDetail: {
        allOf: [
          { $ref: '#/components/schemas/SessionSummary' },
          {
            type: 'object',
            properties: {
              historyLength: { type: 'integer' },
              recentMessages: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    role: { type: 'string', enum: ['user', 'assistant'] },
                    content: { type: 'string' },
                    timestamp: { type: 'string', format: 'date-time' },
                  },
                },
              },
            },
          },
        ],
      },
      ChatReply: {
        type: 'object',
        properties: {
          sessionId: { type: 'string', format: 'uuid' },
          reply: { type: 'string', example: 'The capital of France is Paris.' },
          messageCount: { type: 'integer' },
          lastActivityAt: { type: 'string', format: 'date-time' },
        },
      },
      GenerateRequest: {
        type: 'object',
        required: ['userInput'],
        properties: {
          userInput: {
            type: 'string',
            minLength: 1,
            maxLength: 4000,
            example: 'I want legal advice',
            description: 'The prompt to send to the model. Max 4 000 characters (configurable via safeguards.maxMessageChars).',
          },
        },
      },
      GenerateResponse: {
        type: 'object',
        properties: {
          reply: { type: 'string', example: 'Here are some general legal considerations...' },
          model: { type: 'string', example: 'gpt-4o', description: 'The model deployment that produced the response.' },
          usage: {
            type: 'object',
            properties: {
              inputTokens: { type: 'integer', example: 12 },
              outputTokens: { type: 'integer', example: 120 },
              totalTokens: { type: 'integer', example: 132 },
            },
          },
        },
      },
      SearchRequest: {
        type: 'object',
        required: ['query', 'mode'],
        properties: {
          query: {
            type: 'string',
            minLength: 1,
            maxLength: 4000,
            example: 'housing regulations tenant rights',
            description: 'The search query text.',
          },
          mode: {
            type: 'string',
            enum: ['regulations', 'cases'],
            example: 'regulations',
            description: 'Which index to search — "regulations" or "cases".',
          },
          top: {
            type: 'integer',
            minimum: 1,
            maximum: 50,
            default: 10,
            description: 'Maximum number of results to return.',
          },
          skip: {
            type: 'integer',
            minimum: 0,
            default: 0,
            description: 'Number of results to skip (for pagination).',
          },
        },
      },
      SearchResultCaption: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Extractive caption text from the document.' },
          highlights: {
            type: 'string',
            nullable: true,
            description: 'HTML-highlighted version of the caption (only present for semantic search).',
          },
        },
        required: ['text'],
      },
      SearchResultItem: {
        type: 'object',
        properties: {
          score: {
            type: 'number',
            nullable: true,
            description: 'Relevance score assigned by Azure AI Search.',
          },
          captions: {
            type: 'array',
            nullable: true,
            items: { $ref: '#/components/schemas/SearchResultCaption' },
            description: 'Extractive captions from semantic search — the most relevant text excerpts in the document.',
          },
          document: {
            type: 'object',
            additionalProperties: true,
            description: 'The raw document fields from the search index.',
          },
        },
      },
      SearchResponse: {
        type: 'object',
        properties: {
          mode: { type: 'string', enum: ['regulations', 'cases'] },
          query: { type: 'string', example: 'housing regulations tenant rights' },
          count: { type: 'integer', nullable: true, description: 'Total matching documents (null if count was not returned).' },
          top: { type: 'integer', example: 10 },
          skip: { type: 'integer', example: 0 },
          results: {
            type: 'array',
            items: { $ref: '#/components/schemas/SearchResultItem' },
          },
          reply: {
            type: 'string',
            nullable: true,
            description: 'AI-synthesized answer generated by Azure AI Foundry using the search hits as grounded context. Null if synthesis failed.',
          },
          model: {
            type: 'string',
            nullable: true,
            description: 'Model deployment that produced the reply.',
          },
          usage: {
            nullable: true,
            type: 'object',
            properties: {
              inputTokens: { type: 'integer' },
              outputTokens: { type: 'integer' },
              totalTokens: { type: 'integer' },
            },
            description: 'Token usage for the synthesis call.',
          },
          synthesisError: {
            type: 'string',
            description: 'Present only when the Foundry synthesis step failed. Search results are still returned.',
          },
        },
      },
    },
  },
  paths: {
    '/health': {
      get: {
        tags: ['System'],
        summary: 'Health check',
        security: [],
        responses: {
          '200': {
            description: 'Server is healthy',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    status: { type: 'string', example: 'ok' },
                    timestamp: { type: 'string', format: 'date-time' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/sessions': {
      post: {
        tags: ['Sessions'],
        summary: 'Create a new chat session',
        description: 'Creates a new session. Returns a `sessionId` to use for subsequent chat messages.',
        responses: {
          '201': {
            description: 'Session created',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SessionCreated' } } },
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
      get: {
        tags: ['Sessions'],
        summary: 'List all sessions',
        description: 'Returns all active sessions sorted by most recently active. Sessions expired by TTL are automatically removed.',
        responses: {
          '200': {
            description: 'Session list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    sessions: { type: 'array', items: { $ref: '#/components/schemas/SessionSummary' } },
                    total: { type: 'integer' },
                  },
                },
              },
            },
          },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/sessions/{id}': {
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Session UUID' },
      ],
      get: {
        tags: ['Sessions'],
        summary: 'Get session details',
        description: 'Returns session metadata and the last 10 messages of the conversation history.',
        responses: {
          '200': { description: 'Session details', content: { 'application/json': { schema: { $ref: '#/components/schemas/SessionDetail' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '404': { description: 'Session not found or expired', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
      delete: {
        tags: ['Sessions'],
        summary: 'Delete a session',
        description: 'Immediately terminates and removes the session from storage.',
        responses: {
          '204': { description: 'Session deleted' },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '404': { description: 'Session not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/sessions/{id}/messages': {
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Session UUID' },
      ],
      post: {
        tags: ['Chat'],
        summary: 'Send a chat message',
        description:
          'Appends the user message to the session history, forwards the full context to Azure AI Foundry, ' +
          'and returns the assistant reply. The session TTL is reset on each successful call.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['message'],
                properties: { message: { type: 'string', minLength: 1, maxLength: 32000, example: 'What is the capital of France?' } },
              },
            },
          },
        },
        responses: {
          '200': { description: 'Assistant reply', content: { 'application/json': { schema: { $ref: '#/components/schemas/ChatReply' } } } },
          '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '404': { description: 'Session not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '502': { description: 'Azure AI Foundry error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/generate': {
      post: {
        tags: ['Generate'],
        summary: 'Single-turn AI response',
        description:
          'Sends a single prompt to the Azure OpenAI Responses API and returns one reply. ' +
          'No session or conversation history is involved — each call is fully independent. ' +
          'Uses the system prompt configured in `azure.systemPrompt`.',
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: { $ref: '#/components/schemas/GenerateRequest' } },
          },
        },
        responses: {
          '200': {
            description: 'AI-generated response',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GenerateResponse' } } },
          },
          '400': { description: 'Validation error — userInput missing, empty, or too long', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '401': { description: 'Unauthorized — missing or invalid X-API-Key', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '413': { description: 'Payload too large', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '429': { description: 'Rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '502': { description: 'Azure OpenAI Responses API error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '504': { description: 'Azure call timed out', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/search': {
      post: {
        tags: ['Search'],
        summary: 'Search regulations or cases',
        description:
          'Searches the Azure AI Search index for the given mode ("regulations" or "cases"). ' +
          'Uses semantic search when a semanticConfig is configured for the mode; falls back to simple search otherwise. ' +
          'After retrieving ranked documents, the top hits are sent to Azure AI Foundry as grounded context and a synthesized text answer is generated. ' +
          'The response includes both the raw search results and the AI-generated `reply`. ' +
          'If Foundry synthesis fails, raw search results are still returned with a `synthesisError` field.',
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: { $ref: '#/components/schemas/SearchRequest' } },
          },
        },
        responses: {
          '200': {
            description: 'Search results',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SearchResponse' } } },
          },
          '400': { description: 'Validation error — query missing, empty, too long, or invalid mode', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '401': { description: 'Unauthorized — missing or invalid X-API-Key', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '413': { description: 'Payload too large', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '429': { description: 'Rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '502': { description: 'Azure AI Search returned an error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '503': { description: 'Search mode not configured in config.yaml', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          '504': { description: 'Azure AI Search request timed out', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
  },
};

export default spec;
