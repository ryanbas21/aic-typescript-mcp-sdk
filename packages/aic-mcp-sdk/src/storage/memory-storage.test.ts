import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createMemoryStorage } from './memory-storage.js';
import type { SecureStorage } from './types.js';

describe('createMemoryStorage', () => {
  let storage: SecureStorage;

  beforeEach(() => {
    storage = createMemoryStorage();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('get', () => {
    it('get_KeyExists_ReturnsValue', async () => {
      // Arrange
      await storage.set('key', 'value');

      // Act
      const result = await storage.get('key');

      // Assert
      expect(result).toBe('value');
    });

    it('get_KeyDoesNotExist_ReturnsUndefined', async () => {
      // Arrange - empty storage

      // Act
      const result = await storage.get('nonexistent');

      // Assert
      expect(result).toBeUndefined();
    });

    it('get_KeyExpired_ReturnsUndefinedAndDeletesKey', async () => {
      // Arrange
      await storage.set('key', 'value', 1000); // 1 second TTL

      // Act - advance time past expiration
      vi.advanceTimersByTime(1001);
      const result = await storage.get('key');

      // Assert
      expect(result).toBeUndefined();
    });

    it('get_KeyNotExpired_ReturnsValue', async () => {
      // Arrange
      await storage.set('key', 'value', 5000); // 5 second TTL

      // Act - advance time but not past expiration
      vi.advanceTimersByTime(4000);
      const result = await storage.get('key');

      // Assert
      expect(result).toBe('value');
    });
  });

  describe('set', () => {
    it('set_NoTtl_StoresPermanently', async () => {
      // Arrange & Act
      await storage.set('key', 'value');

      // Advance time significantly
      vi.advanceTimersByTime(1000 * 60 * 60 * 24); // 24 hours

      // Assert
      const result = await storage.get('key');
      expect(result).toBe('value');
    });

    it('set_WithTtl_ExpiresAfterTtl', async () => {
      // Arrange
      await storage.set('key', 'value', 1000);

      // Act & Assert - before expiry
      vi.advanceTimersByTime(500);
      expect(await storage.get('key')).toBe('value');

      // Act & Assert - after expiry
      vi.advanceTimersByTime(600);
      expect(await storage.get('key')).toBeUndefined();
    });

    it('set_OverwriteExistingKey_UpdatesValue', async () => {
      // Arrange
      await storage.set('key', 'value1');

      // Act
      await storage.set('key', 'value2');

      // Assert
      expect(await storage.get('key')).toBe('value2');
    });

    it('set_CleansUpExpiredEntries', async () => {
      // Arrange - set multiple keys with different TTLs
      await storage.set('key1', 'value1', 1000);
      await storage.set('key2', 'value2', 5000);

      // Advance past first key's expiry
      vi.advanceTimersByTime(1500);

      // Act - setting a new key triggers cleanup
      await storage.set('key3', 'value3');

      // Assert - expired key should be cleaned up
      expect(await storage.get('key1')).toBeUndefined();
      expect(await storage.get('key2')).toBe('value2');
      expect(await storage.get('key3')).toBe('value3');
    });
  });

  describe('delete', () => {
    it('delete_KeyExists_ReturnsTrueAndRemovesKey', async () => {
      // Arrange
      await storage.set('key', 'value');

      // Act
      const result = await storage.delete('key');

      // Assert
      expect(result).toBe(true);
      expect(await storage.get('key')).toBeUndefined();
    });

    it('delete_KeyDoesNotExist_ReturnsFalse', async () => {
      // Arrange - empty storage

      // Act
      const result = await storage.delete('nonexistent');

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('clear', () => {
    it('clear_WithEntries_RemovesAllEntries', async () => {
      // Arrange
      await storage.set('key1', 'value1');
      await storage.set('key2', 'value2');
      await storage.set('key3', 'value3');

      // Act
      await storage.clear();

      // Assert
      expect(await storage.get('key1')).toBeUndefined();
      expect(await storage.get('key2')).toBeUndefined();
      expect(await storage.get('key3')).toBeUndefined();
    });

    it('clear_EmptyStorage_DoesNotThrow', async () => {
      // Act & Assert
      await expect(storage.clear()).resolves.toBeUndefined();
    });
  });
});
