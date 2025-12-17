import type { Cache, CacheEntry } from './types.js';

/** Default TTL: 5 minutes */
const DEFAULT_TTL_MS = 5 * 60 * 1000;

/**
 * Creates an in-memory cache with TTL support.
 *
 * @param defaultTtlMs - Default TTL in milliseconds (default: 5 minutes)
 * @returns A Cache instance
 *
 * @example
 * ```typescript
 * const cache = createMemoryCache<string>(60000); // 1 minute default TTL
 * cache.set('key', 'value');
 * cache.get('key'); // 'value'
 * ```
 */
export const createMemoryCache = <T>(defaultTtlMs: number = DEFAULT_TTL_MS): Cache<T> => {
  const store = new Map<string, CacheEntry<T>>();

  const get = (key: string): T | undefined => {
    const entry = store.get(key);
    if (entry === undefined) {
      return undefined;
    }

    if (Date.now() > entry.expiresAt) {
      store.delete(key);
      return undefined;
    }

    return entry.value;
  };

  const set = (key: string, value: T, ttlMs?: number): void => {
    const now = Date.now();

    // Clean up expired entries to prevent unbounded memory growth
    for (const [k, entry] of store.entries()) {
      if (now > entry.expiresAt) {
        store.delete(k);
      }
    }

    const expiresAt = now + (ttlMs ?? defaultTtlMs);
    store.set(key, { value, expiresAt });
  };

  const deleteKey = (key: string): boolean => {
    return store.delete(key);
  };

  const clear = (): void => {
    store.clear();
  };

  return {
    get,
    set,
    delete: deleteKey,
    clear,
  };
};
