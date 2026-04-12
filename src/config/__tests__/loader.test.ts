import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { loadConfig, _resetConfig } from '../loader';
import { AppConfig } from '../types';

// Mock external dependencies
jest.mock('fs');
jest.mock('js-yaml');

const mockFs = fs as jest.Mocked<typeof fs>;
const mockYaml = yaml as jest.Mocked<typeof yaml>;

describe('config/loader', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    _resetConfig();
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
    _resetConfig();
  });

  describe('loadConfig', () => {
    describe('from YAML file', () => {
      it('should load and parse valid config.yaml', () => {
        const mockConfig = {
          mode: 'dev',
          server: { port: 3000, host: '0.0.0.0' },
          auth: { apiKeys: [{ name: 'test', key: 'test-key-123' }] },
          azure: {
            projectEndpoint: 'https://test.services.ai.azure.com/api/projects/test',
            deployment: 'gpt-4',
            agentName: 'test-agent',
            systemPrompt: 'You are helpful.',
            temperature: 0.7,
            maxTokens: 2048,
            responsesApiVersion: '2025-03-01-preview',
          },
          redis: { host: 'localhost', port: 6379, password: '', db: 0 },
          session: { timeoutMinutes: 30, maxHistoryLength: 100 },
          safeguards: {
            requestBodyLimitKb: 64,
            rateLimitWindowMs: 60000,
            rateLimitMaxRequests: 60,
            sessionCreateLimitMax: 10,
            maxMessageChars: 4000,
            maxSessionsPerClient: 10,
            maxTotalSessions: 200,
            azureTimeoutMs: 30000,
          },
          cors: { allowedOrigins: [], allowCredentials: true },
          search: {
            dnsSuffix: 'search.windows.net',
            apiVersion: '2023-11-01',
          },
        };

        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue('yaml content');
        mockYaml.load.mockReturnValue(mockConfig);

        const config = loadConfig();

        expect(mockFs.existsSync).toHaveBeenCalledWith(expect.stringContaining('config.yaml'));
        expect(mockFs.readFileSync).toHaveBeenCalled();
        expect(mockYaml.load).toHaveBeenCalled();
        expect(config.mode).toBe('dev');
        expect(config.auth.apiKeys).toHaveLength(1);
      });

      it('should use custom CONFIG_PATH if provided', () => {
        process.env.CONFIG_PATH = '/custom/path/config.yaml';
        const mockConfig = {
          mode: 'prod',
          server: { port: 8080, host: '0.0.0.0' },
          auth: { apiKeys: [{ name: 'prod', key: 'prod-key' }] },
          azure: {
            projectEndpoint: 'https://prod.services.ai.azure.com/api/projects/prod',
            deployment: 'gpt-4',
          },
          redis: { host: 'redis.prod', port: 6379, db: 0 },
          session: { timeoutMinutes: 30, maxHistoryLength: 100 },
          safeguards: {
            requestBodyLimitKb: 64,
            rateLimitWindowMs: 60000,
            rateLimitMaxRequests: 60,
            sessionCreateLimitMax: 10,
            maxMessageChars: 4000,
            maxSessionsPerClient: 10,
            maxTotalSessions: 200,
            azureTimeoutMs: 30000,
          },
          cors: { allowedOrigins: ['https://example.com'], allowCredentials: true },
          search: { dnsSuffix: 'search.windows.net', apiVersion: '2023-11-01' },
        };

        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue('yaml content');
        mockYaml.load.mockReturnValue(mockConfig);

        loadConfig();

        expect(mockFs.existsSync).toHaveBeenCalledWith('/custom/path/config.yaml');
      });

      it('should throw error for invalid config schema', () => {
        const invalidConfig = {
          mode: 'invalid-mode',
          // Missing required fields
        };

        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue('yaml content');
        mockYaml.load.mockReturnValue(invalidConfig);

        expect(() => loadConfig()).toThrow(/Invalid configuration/);
      });

      it('should cache config after first load', () => {
        const mockConfig = {
          mode: 'dev',
          server: { port: 3000, host: '0.0.0.0' },
          auth: { apiKeys: [{ name: 'test', key: 'test-key' }] },
          azure: {
            projectEndpoint: 'https://test.services.ai.azure.com/api/projects/test',
            deployment: 'gpt-4',
          },
          redis: { host: 'localhost', port: 6379, db: 0 },
          session: { timeoutMinutes: 30, maxHistoryLength: 100 },
          safeguards: {
            requestBodyLimitKb: 64,
            rateLimitWindowMs: 60000,
            rateLimitMaxRequests: 60,
            sessionCreateLimitMax: 10,
            maxMessageChars: 4000,
            maxSessionsPerClient: 10,
            maxTotalSessions: 200,
            azureTimeoutMs: 30000,
          },
          cors: { allowedOrigins: [], allowCredentials: true },
          search: { dnsSuffix: 'search.windows.net', apiVersion: '2023-11-01' },
        };

        mockFs.existsSync.mockReturnValue(true);
        mockFs.readFileSync.mockReturnValue('yaml content');
        mockYaml.load.mockReturnValue(mockConfig);

        const config1 = loadConfig();
        const config2 = loadConfig();

        expect(config1).toBe(config2);
        expect(mockFs.readFileSync).toHaveBeenCalledTimes(1);
      });
    });

    describe('from environment variables', () => {
      beforeEach(() => {
        mockFs.existsSync.mockReturnValue(false);
      });

      it('should build config from env vars when file does not exist', () => {
        process.env.BACKEND_API_KEY = 'env-key-123';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://env.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'env-project';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';
        process.env.AZURE_AGENT_NAME = 'env-agent';

        const config = loadConfig();

        expect(config.auth.apiKeys[0].key).toBe('env-key-123');
        expect(config.azure.projectEndpoint).toContain('env-project');
        expect(config.azure.deployment).toBe('gpt-4');
      });

      it('should use APP_MODE from env', () => {
        process.env.APP_MODE = 'stage';
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();
        expect(config.mode).toBe('stage');
      });

      it('should parse PORT as integer', () => {
        process.env.PORT = '9000';
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();
        expect(config.server.port).toBe(9000);
        expect(typeof config.server.port).toBe('number');
      });

      it('should parse numeric env vars correctly', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';
        process.env.REDIS_PORT = '6380';
        process.env.REDIS_DB = '2';
        process.env.SESSION_TIMEOUT_MINUTES = '45';
        process.env.SESSION_MAX_HISTORY = '150';
        process.env.AZURE_TEMPERATURE = '1.2';
        process.env.AZURE_MAX_TOKENS = '4096';

        const config = loadConfig();

        expect(config.redis.port).toBe(6380);
        expect(config.redis.db).toBe(2);
        expect(config.session.timeoutMinutes).toBe(45);
        expect(config.session.maxHistoryLength).toBe(150);
        expect(config.azure.temperature).toBe(1.2);
        expect(config.azure.maxTokens).toBe(4096);
      });

      it('should parse CORS_ORIGIN as comma-separated list', () => {
        process.env.CORS_ORIGIN = 'https://app1.com, https://app2.com , https://app3.com';
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();

        expect(config.cors.allowedOrigins).toEqual([
          'https://app1.com',
          'https://app2.com',
          'https://app3.com',
        ]);
      });

      it('should handle empty CORS_ORIGIN', () => {
        process.env.CORS_ORIGIN = '';
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();
        expect(config.cors.allowedOrigins).toEqual([]);
      });

      it('should include search.regulations when all REG env vars are present', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';
        process.env.REG_SEARCH_SERVICE = 'reg-service';
        process.env.REG_SEARCH_KEY = 'reg-key';
        process.env.REG_SEARCH_INDEX = 'reg-index';
        process.env.REG_SEMANTIC_CONFIG = 'reg-semantic';

        const config = loadConfig();

        expect(config.search.regulations).toBeDefined();
        expect(config.search.regulations?.service).toBe('reg-service');
        expect(config.search.regulations?.key).toBe('reg-key');
        expect(config.search.regulations?.index).toBe('reg-index');
        expect(config.search.regulations?.semanticConfig).toBe('reg-semantic');
      });

      it('should exclude search.regulations when REG env vars are incomplete', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';
        process.env.REG_SEARCH_SERVICE = 'reg-service';
        // Missing REG_SEARCH_KEY and REG_SEARCH_INDEX

        const config = loadConfig();
        expect(config.search.regulations).toBeUndefined();
      });

      it('should include search.cases when all CASES env vars are present', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';
        process.env.CASES_SEARCH_SERVICE = 'cases-service';
        process.env.CASES_SEARCH_KEY = 'cases-key';
        process.env.CASES_SEARCH_INDEX = 'cases-index';

        const config = loadConfig();

        expect(config.search.cases).toBeDefined();
        expect(config.search.cases?.service).toBe('cases-service');
        expect(config.search.cases?.semanticConfig).toBeUndefined();
      });

      it('should use default values when optional env vars are missing', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/api';
        process.env.AZURE_PROJECT_NAME = 'test';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();

        expect(config.mode).toBe('prod');
        expect(config.server.port).toBe(8080);
        expect(config.server.host).toBe('0.0.0.0');
        expect(config.azure.agentName).toBe('chat-backend-agent');
        expect(config.azure.systemPrompt).toBe('You are a helpful assistant.');
        expect(config.azure.temperature).toBe(0.7);
        expect(config.azure.maxTokens).toBe(2048);
        expect(config.redis.host).toBe('localhost');
        expect(config.redis.port).toBe(6379);
        expect(config.session.timeoutMinutes).toBe(30);
        expect(config.safeguards.requestBodyLimitKb).toBe(64);
      });

      it('should combine AZURE_PROJECT_ENDPOINT and AZURE_PROJECT_NAME', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com/';
        process.env.AZURE_PROJECT_NAME = 'my-project';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();

        expect(config.azure.projectEndpoint).toBe(
          'https://test.services.ai.azure.com/api/projects/my-project'
        );
      });

      it('should strip trailing slashes from AZURE_PROJECT_ENDPOINT', () => {
        process.env.BACKEND_API_KEY = 'key';
        process.env.AZURE_PROJECT_ENDPOINT = 'https://test.services.ai.azure.com///';
        process.env.AZURE_PROJECT_NAME = 'proj';
        process.env.AZURE_DEPLOYMENT = 'gpt-4';

        const config = loadConfig();

        expect(config.azure.projectEndpoint).toBe(
          'https://test.services.ai.azure.com/api/projects/proj'
        );
      });

      it('should throw error when required env vars are missing', () => {
        process.env.BACKEND_API_KEY = '';

        expect(() => loadConfig()).toThrow(/Invalid configuration/);
      });
    });
  });

  describe('_resetConfig', () => {
    it('should allow config to be reloaded', () => {
      const mockConfig1 = {
        mode: 'dev',
        server: { port: 3000, host: '0.0.0.0' },
        auth: { apiKeys: [{ name: 'test1', key: 'key1' }] },
        azure: {
          projectEndpoint: 'https://test1.services.ai.azure.com/api/projects/test1',
          deployment: 'gpt-4',
        },
        redis: { host: 'localhost', port: 6379, db: 0 },
        session: { timeoutMinutes: 30, maxHistoryLength: 100 },
        safeguards: {
          requestBodyLimitKb: 64,
          rateLimitWindowMs: 60000,
          rateLimitMaxRequests: 60,
          sessionCreateLimitMax: 10,
          maxMessageChars: 4000,
          maxSessionsPerClient: 10,
          maxTotalSessions: 200,
          azureTimeoutMs: 30000,
        },
        cors: { allowedOrigins: [], allowCredentials: true },
        search: { dnsSuffix: 'search.windows.net', apiVersion: '2023-11-01' },
      };

      const mockConfig2 = {
        ...mockConfig1,
        mode: 'prod',
        auth: { apiKeys: [{ name: 'test2', key: 'key2' }] },
      };

      mockFs.existsSync.mockReturnValue(true);
      mockFs.readFileSync.mockReturnValue('yaml content');

      mockYaml.load.mockReturnValueOnce(mockConfig1);
      const config1 = loadConfig();

      _resetConfig();

      mockYaml.load.mockReturnValueOnce(mockConfig2);
      const config2 = loadConfig();

      expect(config1.auth.apiKeys[0].key).toBe('key1');
      expect(config2.auth.apiKeys[0].key).toBe('key2');
      expect(config1).not.toBe(config2);
    });
  });
});
