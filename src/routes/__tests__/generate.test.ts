import request from 'supertest';
import express, { Application } from 'express';
import generateRouter from '../../routes/generate';
import { errorHandler } from '../../middleware/errorHandler';
import { generateResponse } from '../../services/responsesService';
import { loadConfig } from '../../config/loader';

jest.mock('../../services/responsesService');
jest.mock('../../config/loader');

const mockGenerateResponse = generateResponse as jest.MockedFunction<typeof generateResponse>;
const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('routes/generate', () => {
  let app: Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use('/generate', generateRouter);
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

  describe('POST /generate', () => {
    it('should generate a response successfully', async () => {
      mockGenerateResponse.mockResolvedValue({
        reply: 'Generated response',
        model: 'gpt-4',
        usage: {
          inputTokens: 10,
          outputTokens: 20,
          totalTokens: 30,
        },
      });

      const response = await request(app)
        .post('/generate')
        .send({ userInput: 'Hello AI' });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        reply: 'Generated response',
        model: 'gpt-4',
        usage: {
          inputTokens: 10,
          outputTokens: 20,
          totalTokens: 30,
        },
      });
      expect(mockGenerateResponse).toHaveBeenCalledWith('Hello AI');
    });

    it('should return 400 for empty userInput', async () => {
      const response = await request(app)
        .post('/generate')
        .send({ userInput: '' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('must not be empty');
    });

    it('should return 400 for missing userInput field', async () => {
      const response = await request(app)
        .post('/generate')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when userInput exceeds character limit', async () => {
      const longInput = 'a'.repeat(4001);

      const response = await request(app)
        .post('/generate')
        .send({ userInput: longInput });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('4000-character limit');
    });

    it('should accept userInput at exact character limit', async () => {
      const exactLimitInput = 'a'.repeat(4000);

      mockGenerateResponse.mockResolvedValue({
        reply: 'Response',
        model: 'gpt-4',
        usage: { inputTokens: 100, outputTokens: 50, totalTokens: 150 },
      });

      const response = await request(app)
        .post('/generate')
        .send({ userInput: exactLimitInput });

      expect(response.status).toBe(200);
    });

    it('should handle Azure timeout gracefully', async () => {
      mockGenerateResponse.mockImplementation(
        () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error('timeout')), 100))
      );

      const response = await request(app)
        .post('/generate')
        .send({ userInput: 'Test' });

      expect(response.status).toBe(504);
      expect(response.body.error.code).toBe('UPSTREAM_TIMEOUT');
      expect(response.body.error.message).toContain('timed out');
    }, 15000);

    it('should handle Azure errors as UpstreamError', async () => {
      mockGenerateResponse.mockRejectedValue(new Error('Azure service unavailable'));

      const response = await request(app)
        .post('/generate')
        .send({ userInput: 'Test' });

      expect(response.status).toBe(502);
      expect(response.body.error.code).toBe('UPSTREAM_ERROR');
      expect(response.body.error.message).toContain('Azure OpenAI Responses error');
    });

    it('should handle non-Error rejections', async () => {
      mockGenerateResponse.mockRejectedValue('String error');

      const response = await request(app)
        .post('/generate')
        .send({ userInput: 'Test' });

      expect(response.status).toBe(502);
      expect(response.body.error.message).toContain('String error');
    });
  });
});
