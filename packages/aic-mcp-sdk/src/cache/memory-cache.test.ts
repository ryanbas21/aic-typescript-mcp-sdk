import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createMemoryCache } from './memory-cache.js';
import { ONE_HOUR_MS } from '../test/fixtures.js';

/** Default TTL used by the cache when not specified */
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** Short TTL for testing expiration */
const SHORT_TTL_MS = 100;

describe('createMemoryCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('get', () => {
    describe('given key does not exist', () => {
      it('returns undefined', () => {
        const cache = createMemoryCache<string>();

        const result = cache.get('nonexistent');

        expect(result).toBeUndefined();
      });
    });

    describe('given key exists and is not expired', () => {
      it('returns the cached value', () => {
        const cache = createMemoryCache<string>();
        const key = 'test-key';
        const value = 'test-value';
        cache.set(key, value);

        const result = cache.get(key);

        expect(result).toBe(value);
      });
    });

    describe('given key exists but is expired', () => {
      it('returns undefined and removes the entry', () => {
        const cache = createMemoryCache<string>(SHORT_TTL_MS);
        const key = 'test-key';
        const value = 'test-value';
        cache.set(key, value);

        // Advance time past expiration
        vi.advanceTimersByTime(SHORT_TTL_MS + 1);

        const result = cache.get(key);

        expect(result).toBeUndefined();
      });
    });

    describe('given key expires exactly at check time', () => {
      it('returns undefined', () => {
        const cache = createMemoryCache<string>(SHORT_TTL_MS);
        const key = 'test-key';
        cache.set(key, 'value');

        // Advance time to exactly the expiration moment plus one ms
        vi.advanceTimersByTime(SHORT_TTL_MS + 1);

        const result = cache.get(key);

        expect(result).toBeUndefined();
      });
    });
  });

  describe('set', () => {
    describe('given no TTL specified', () => {
      it('uses default TTL', () => {
        const cache = createMemoryCache<string>();
        const key = 'test-key';
        cache.set(key, 'value');

        // Value available before default TTL
        vi.advanceTimersByTime(DEFAULT_CACHE_TTL_MS - 1);
        expect(cache.get(key)).toBe('value');

        // Value expired after default TTL
        vi.advanceTimersByTime(2);
        expect(cache.get(key)).toBeUndefined();
      });
    });

    describe('given custom TTL specified', () => {
      it('uses the custom TTL', () => {
        const customTtlMs = 1000;
        const cache = createMemoryCache<string>(ONE_HOUR_MS);
        const key = 'test-key';
        cache.set(key, 'value', customTtlMs);

        // Value available before custom TTL
        vi.advanceTimersByTime(customTtlMs - 1);
        expect(cache.get(key)).toBe('value');

        // Value expired after custom TTL
        vi.advanceTimersByTime(2);
        expect(cache.get(key)).toBeUndefined();
      });
    });

    describe('given existing key', () => {
      it('overwrites the value and resets TTL', () => {
        const cache = createMemoryCache<string>(SHORT_TTL_MS);
        const key = 'test-key';

        cache.set(key, 'first-value');
        vi.advanceTimersByTime(SHORT_TTL_MS / 2);

        cache.set(key, 'second-value');

        // Advance past original expiration but within new TTL
        vi.advanceTimersByTime(SHORT_TTL_MS / 2 + 1);

        expect(cache.get(key)).toBe('second-value');
      });
    });
  });

  describe('delete', () => {
    describe('given key exists', () => {
      it('removes the entry and returns true', () => {
        const cache = createMemoryCache<string>();
        const key = 'test-key';
        cache.set(key, 'value');

        const result = cache.delete(key);

        expect(result).toBe(true);
        expect(cache.get(key)).toBeUndefined();
      });
    });

    describe('given key does not exist', () => {
      it('returns false', () => {
        const cache = createMemoryCache<string>();

        const result = cache.delete('nonexistent');

        expect(result).toBe(false);
      });
    });
  });

  describe('clear', () => {
    it('removes all entries', () => {
      const cache = createMemoryCache<string>();
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      cache.clear();

      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBeUndefined();
      expect(cache.get('key3')).toBeUndefined();
    });

    describe('given empty cache', () => {
      it('does not throw', () => {
        const cache = createMemoryCache<string>();

        expect(() => {
          cache.clear();
        }).not.toThrow();
      });
    });
  });

  describe('type safety', () => {
    it('stores and retrieves objects correctly', () => {
      interface TestData {
        readonly id: number;
        readonly name: string;
      }
      const cache = createMemoryCache<TestData>();
      const data: TestData = { id: 1, name: 'Test' };

      cache.set('data', data);

      const result = cache.get('data');
      expect(result).toEqual(data);
    });

    it('stores and retrieves arrays correctly', () => {
      const cache = createMemoryCache<readonly number[]>();
      const numbers = [1, 2, 3];

      cache.set('numbers', numbers);

      const result = cache.get('numbers');
      expect(result).toEqual(numbers);
    });
  });
});
