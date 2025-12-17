/**
 * Generic cache interface for storing values with optional TTL.
 */
export interface Cache<T> {
  /**
   * Gets a value from the cache.
   * @param key - The cache key
   * @returns The cached value or undefined if not found/expired
   */
  readonly get: (key: string) => T | undefined;

  /**
   * Sets a value in the cache.
   * @param key - The cache key
   * @param value - The value to cache
   * @param ttlMs - Optional TTL in milliseconds (overrides default)
   */
  readonly set: (key: string, value: T, ttlMs?: number) => void;

  /**
   * Deletes a value from the cache.
   * @param key - The cache key
   * @returns true if the key existed, false otherwise
   */
  readonly delete: (key: string) => boolean;

  /**
   * Clears all values from the cache.
   */
  readonly clear: () => void;
}

/**
 * Internal cache entry with expiration timestamp.
 */
export interface CacheEntry<T> {
  readonly value: T;
  readonly expiresAt: number;
}
