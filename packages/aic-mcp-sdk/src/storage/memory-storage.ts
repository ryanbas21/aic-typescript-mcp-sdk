import type { SecureStorage, StorageEntry } from './types.js';

/**
 * Creates an in-memory secure storage implementation.
 *
 * This implementation stores values in memory and automatically
 * cleans up expired entries. Values are lost when the process exits.
 *
 * @returns A SecureStorage instance
 *
 * @example
 * ```typescript
 * const storage = createMemoryStorage();
 * await storage.set('pkce:abc123', 'verifier', 600000); // 10 min TTL
 * const verifier = await storage.get('pkce:abc123');
 * ```
 */
export const createMemoryStorage = (): SecureStorage => {
  const store = new Map<string, StorageEntry>();

  const cleanupExpired = (): void => {
    const now = Date.now();
    for (const [key, entry] of store.entries()) {
      if (entry.expiresAt !== undefined && now > entry.expiresAt) {
        store.delete(key);
      }
    }
  };

  const get = (key: string): Promise<string | undefined> => {
    const entry = store.get(key);
    if (entry === undefined) {
      return Promise.resolve(undefined);
    }

    if (entry.expiresAt !== undefined && Date.now() > entry.expiresAt) {
      store.delete(key);
      return Promise.resolve(undefined);
    }

    return Promise.resolve(entry.value);
  };

  const set = (key: string, value: string, ttlMs?: number): Promise<void> => {
    // Clean up expired entries to prevent unbounded memory growth
    cleanupExpired();

    const expiresAt = ttlMs !== undefined ? Date.now() + ttlMs : undefined;
    store.set(key, { value, expiresAt });
    return Promise.resolve();
  };

  const deleteKey = (key: string): Promise<boolean> => {
    return Promise.resolve(store.delete(key));
  };

  const clear = (): Promise<void> => {
    store.clear();
    return Promise.resolve();
  };

  return {
    get,
    set,
    delete: deleteKey,
    clear,
  };
};
