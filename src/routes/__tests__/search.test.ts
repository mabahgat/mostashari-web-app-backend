import request from 'supertest';
import express, { Application } from 'express';
import searchRouter from '../../routes/search';
import { errorHandler } from '../../middleware/errorHandler';
import { search } from '../../services/searchService';
import { synthesizeSearchResults } from '../../services/responsesService';
import { loadConfig } from '../../config/loader';

jest.mock('../../services/searchService');
jest.mock('../../services/responsesService');
jest.mock('../../config/loader');

const mockSearch = search as jest.MockedFunction<typeof search>;
const mockSynthesize = synthesizeSearchResults as jest.MockedFunction<typeof synthesizeSearchResults>;
const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('routes/search', () => {
  let app: Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use('/search', searchRouter);
    app.use(errorHandler);

    mockLoadConfig.mockReturnValue({
      mode: 'dev',
      safeguards: {
        maxMessageChars: 4000,
        azureTimeoutMs: 30000,
      },
    } as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /search', () => {
    it('should perform search and synthesis successfully', async () => {
      const searchResults = {
        mode: 'regulations' as const,
        query: 'test query',
        count: 5,
        results: [
          { score: 0.9, captions: [{ text: 'Result 1' }], document: { id: '1' } },
          { score: 0.8, captions: [{ text: 'Result 2' }], document: { id: '2' } },
        ],
      };

      mockSearch.mockResolvedValue(searchResults);
      mockSynthesize.mockResolvedValue({
        reply: 'Synthesized answer',
        model: 'gpt-4',
        usage: { inputTokens: 50, outputTokens: 100, totalTokens: 150 },
      });

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test query',
          mode: 'regulations',
          top: 10,
          skip: 0,
        });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        mode: 'regulations',
        query: 'test query',
        count: 5,
        top: 10,
        skip: 0,
        results: searchResults.results,
        reply: 'Synthesized answer',
        model: 'gpt-4',
        usage: { inputTokens: 50, outputTokens: 100, totalTokens: 150 },
      });
    });

    it('should use default top and skip values', async () => {
      mockSearch.mockResolvedValue({
        mode: 'cases',
        query: 'test',
        count: 1,
        results: [],
      });
      mockSynthesize.mockResolvedValue({
        reply: 'Answer',
        model: 'gpt-4',
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
      });

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'cases',
        });

      expect(response.status).toBe(200);
      expect(response.body.top).toBe(10);
      expect(response.body.skip).toBe(0);
    });

    it('should return 400 for empty query', async () => {
      const response = await request(app)
        .post('/search')
        .send({
          query: '',
          mode: 'regulations',
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('must not be empty');
    });

    it('should return 400 for invalid mode', async () => {
      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'invalid',
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('must be "regulations" or "cases"');
    });

    it('should return 400 when query exceeds character limit', async () => {
      const longQuery = 'a'.repeat(4001);

      const response = await request(app)
        .post('/search')
        .send({
          query: longQuery,
          mode: 'regulations',
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('4000-character limit');
    });

    it('should validate top parameter range', async () => {
      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
          top: 100,
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should validate skip parameter is non-negative', async () => {
      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
          skip: -1,
        });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle search timeout gracefully', async () => {
      mockSearch.mockImplementation(
        () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error('timeout')), 100))
      );

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
        });

      expect(response.status).toBe(504);
      expect(response.body.error.code).toBe('UPSTREAM_TIMEOUT');
      expect(response.body.error.message).toContain('Azure AI Search');
    }, 15000);

    it('should handle unconfigured search mode', async () => {
      mockSearch.mockRejectedValue(
        new Error('Search mode "regulations" is not configured in config.yaml')
      );

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
        });

      expect(response.status).toBe(503);
      expect(response.body.error.code).toBe('SEARCH_NOT_CONFIGURED');
    });

    it('should handle search errors', async () => {
      mockSearch.mockRejectedValue(new Error('Search service unavailable'));

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
        });

      expect(response.status).toBe(502);
      expect(response.body.error.code).toBe('UPSTREAM_ERROR');
      expect(response.body.error.message).toContain('Azure AI Search error');
    });

    it('should return search results even if synthesis fails', async () => {
      const searchResults = {
        mode: 'regulations' as const,
        query: 'test',
        count: 2,
        results: [
          { score: 0.9, captions: undefined, document: { id: '1' } },
        ],
      };

      mockSearch.mockResolvedValue(searchResults);
      mockSynthesize.mockRejectedValue(new Error('Synthesis failed'));

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
        });

      expect(response.status).toBe(200);
      expect(response.body.results).toEqual(searchResults.results);
      expect(response.body.reply).toBeNull();
      expect(response.body.model).toBeNull();
      expect(response.body.usage).toBeNull();
      expect(response.body.synthesisError).toContain('Synthesis failed');
    });

    it('should handle synthesis timeout gracefully', async () => {
      mockSearch.mockResolvedValue({
        mode: 'cases',
        query: 'test',
        count: 1,
        results: [{ score: 0.5, captions: undefined, document: {} }],
      });

      mockSynthesize.mockImplementation(
        () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error('timeout')), 100))
      );

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'cases',
        });

      expect(response.status).toBe(200);
      expect(response.body.reply).toBeNull();
      expect(response.body.synthesisError).toBeDefined();
      expect(response.body.synthesisError).toContain('timed out');
    }, 15000);

    it('should handle non-Error search rejections', async () => {
      mockSearch.mockRejectedValue('String error');

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
        });

      expect(response.status).toBe(502);
      expect(response.body.error.message).toContain('String error');
    });

    it('should handle synthesis non-Error rejections', async () => {
      mockSearch.mockResolvedValue({
        mode: 'regulations',
        query: 'test',
        count: 1,
        results: [],
      });
      mockSynthesize.mockRejectedValue('Synthesis string error');

      const response = await request(app)
        .post('/search')
        .send({
          query: 'test',
          mode: 'regulations',
        });

      expect(response.status).toBe(200);
      expect(response.body.synthesisError).toBe('Synthesis string error');
    });
  });
});
