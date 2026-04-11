import { loadConfig } from '../config/loader';
import { ISessionStore } from './stores/ISessionStore';
import { RedisSessionStore } from './stores/RedisSessionStore';
import { InMemorySessionStore } from './stores/InMemorySessionStore';

let storeInstance: ISessionStore | null = null;

export function getSessionStore(): ISessionStore {
  if (storeInstance) {
    return storeInstance;
  }

  const { mode } = loadConfig();

  if (mode === 'dev') {
    storeInstance = new InMemorySessionStore();
  } else {
    storeInstance = new RedisSessionStore();
  }

  return storeInstance;
}

/** Reset singleton — used in tests only. */
export function _resetSessionStore(): void {
  storeInstance = null;
}
