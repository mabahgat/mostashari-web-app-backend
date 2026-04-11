import Redis from 'ioredis';
import { loadConfig } from '../config/loader';
import logger from './logger';

let redisClient: Redis | null = null;

export function getRedisClient(): Redis {
  if (redisClient) {
    return redisClient;
  }

  const { redis } = loadConfig();

  redisClient = new Redis({
    host: redis.host,
    port: redis.port,
    password: redis.password || undefined,
    db: redis.db,
    lazyConnect: true,
    retryStrategy: (times) => {
      const delay = Math.min(times * 200, 5000);
      logger.warn(`Redis reconnect attempt #${times}, retry in ${delay}ms`);
      return delay;
    },
  });

  redisClient.on('connect', () => logger.info('Redis connected'));
  redisClient.on('error', (err) => logger.error('Redis error', { error: err.message }));

  return redisClient;
}

export async function connectRedis(): Promise<void> {
  const client = getRedisClient();
  await client.connect();
}
