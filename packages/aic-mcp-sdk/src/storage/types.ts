/**
 * Secure storage interface for tokens and authorization state.
 *
 * This interface abstracts storage of sensitive data like tokens,
 * PKCE verifiers, and authorization state. Implementations can
 * provide encryption, persistence, or platform-specific secure storage.
 */
export interface SecureStorage {
  /**
   * Gets a value from storage.
   * @param key - The storage key
   * @returns The stored value or undefined if not found/expired
   */
  readonly get: (key: string) => Promise<string | undefined>;

  /**
   * Sets a value in storage.
   * @param key - The storage key
   * @param value - The value to store
   * @param ttlMs - Optional TTL in milliseconds after which the value expires
   */
  readonly set: (key: string, value: string, ttlMs?: number) => Promise<void>;

  /**
   * Deletes a value from storage.
   * @param key - The storage key
   * @returns true if the key existed, false otherwise
   */
  readonly delete: (key: string) => Promise<boolean>;

  /**
   * Clears all values from storage.
   */
  readonly clear: () => Promise<void>;
}

/**
 * Internal storage entry with optional expiration timestamp.
 */
export interface StorageEntry {
  readonly value: string;
  readonly expiresAt?: number | undefined;
}
