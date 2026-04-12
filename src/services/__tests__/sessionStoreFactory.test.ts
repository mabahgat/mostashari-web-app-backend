import { getSessionStore, _resetSessionStore } from '../sessionStoreFactory';
import { InMemorySessionStore } from '../stores/InMemorySessionStore';
import { RedisSessionStore } from '../stores/RedisSessionStore';
import { loadConfig } from '../../config/loader';

jest.mock('../../config/loader');
jest.mock('../stores/InMemorySessionStore');
jest.mock('../stores/RedisSessionStore');

const mockLoadConfig = loadConfig as jest.MockedFunction<typeof loadConfig>;

describe('services/sessionStoreFactory', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    _resetSessionStore();
  });

  afterEach(() => {
    _resetSessionStore();
  });

  describe('getSessionStore', () => {
    it('should return InMemorySessionStore in dev mode', () => {
      mockLoadConfig.mockReturnValue({ mode: 'dev' } as any);

      const store = getSessionStore();

      expect(InMemorySessionStore).toHaveBeenCalled();
      expect(store).toBeInstanceOf(InMemorySessionStore);
    });

    it('should return RedisSessionStore in prod mode', () => {
      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);

      const store = getSessionStore();

      expect(RedisSessionStore).toHaveBeenCalled();
      expect(store).toBeInstanceOf(RedisSessionStore);
    });

    it('should return RedisSessionStore in stage mode', () => {
      mockLoadConfig.mockReturnValue({ mode: 'stage' } as any);

      const store = getSessionStore();

      expect(RedisSessionStore).toHaveBeenCalled();
      expect(store).toBeInstanceOf(RedisSessionStore);
    });

    it('should cache store instance', () => {
      mockLoadConfig.mockReturnValue({ mode: 'dev' } as any);

      const store1 = getSessionStore();
      const store2 = getSessionStore();

      expect(store1).toBe(store2);
      expect(InMemorySessionStore).toHaveBeenCalledTimes(1);
    });
  });

  describe('_resetSessionStore', () => {
    it('should allow store to be recreated', () => {
      mockLoadConfig.mockReturnValue({ mode: 'dev' } as any);

      const store1 = getSessionStore();

      _resetSessionStore();

      const store2 = getSessionStore();

      expect(InMemorySessionStore).toHaveBeenCalledTimes(2);
    });

    it('should allow switching store types', () => {
      mockLoadConfig.mockReturnValue({ mode: 'dev' } as any);
      const store1 = getSessionStore();
      expect(store1).toBeInstanceOf(InMemorySessionStore);

      _resetSessionStore();

      mockLoadConfig.mockReturnValue({ mode: 'prod' } as any);
      const store2 = getSessionStore();
      expect(store2).toBeInstanceOf(RedisSessionStore);
    });
  });
});
