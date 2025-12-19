import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createMemoryStorage } from '../storage/memory-storage.js';
import type { SecureStorage } from '../storage/types.js';
import {
  generateState,
  generateNonce,
  createAuthorizationState,
  retrieveAuthorizationState,
  consumeAuthorizationState,
  validateCallbackState,
} from './state.js';

describe('State management utilities', () => {
  let storage: SecureStorage;

  beforeEach(() => {
    storage = createMemoryStorage();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('generateState', () => {
    it('generateState_DefaultLength_Returns32CharString', () => {
      // Act
      const state = generateState();

      // Assert
      expect(state).toHaveLength(32);
    });

    it('generateState_CustomLength_ReturnsRequestedLength', () => {
      // Act
      const state = generateState(64);

      // Assert
      expect(state).toHaveLength(64);
    });

    it('generateState_ContainsOnlyAlphanumeric', () => {
      // Act
      const state = generateState();

      // Assert
      expect(state).toMatch(/^[A-Za-z0-9]+$/);
    });

    it('generateState_GeneratesUniqueValues', () => {
      // Act
      const state1 = generateState();
      const state2 = generateState();
      const state3 = generateState();

      // Assert
      expect(state1).not.toBe(state2);
      expect(state2).not.toBe(state3);
      expect(state1).not.toBe(state3);
    });
  });

  describe('generateNonce', () => {
    it('generateNonce_DefaultLength_Returns32CharString', () => {
      // Act
      const nonce = generateNonce();

      // Assert
      expect(nonce).toHaveLength(32);
    });

    it('generateNonce_GeneratesUniqueValues', () => {
      // Act
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      // Assert
      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe('createAuthorizationState', () => {
    const clientConfig = {
      redirectUri: 'https://app.example.com/callback',
      scopes: ['openid', 'profile'] as const,
    };

    it('createAuthorizationState_NoOptions_CreatesStateWithDefaults', async () => {
      // Act
      const result = await createAuthorizationState(storage, undefined, clientConfig);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.state).toHaveLength(32);
        expect(result.value.nonce).toHaveLength(32);
        expect(result.value.pkce.verifier).toHaveLength(64);
        expect(result.value.pkce.method).toBe('S256');
        expect(result.value.redirectUri).toBe(clientConfig.redirectUri);
        expect(result.value.scopes).toEqual(clientConfig.scopes);
        expect(result.value.resource).toBeUndefined();
      }
    });

    it('createAuthorizationState_WithOptions_UsesProvidedValues', async () => {
      // Arrange
      const options = {
        state: 'custom-state',
        nonce: 'custom-nonce',
        scopes: ['openid', 'email'] as const,
        resource: 'https://api.example.com',
      };

      // Act
      const result = await createAuthorizationState(storage, options, clientConfig);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.state).toBe('custom-state');
        expect(result.value.nonce).toBe('custom-nonce');
        expect(result.value.scopes).toEqual(['openid', 'email']);
        expect(result.value.resource).toBe('https://api.example.com');
      }
    });

    it('createAuthorizationState_StoresStateInStorage', async () => {
      // Act
      const result = await createAuthorizationState(storage, undefined, clientConfig);
      expect(result.isOk()).toBe(true);
      if (!result.isOk()) return;

      // Assert - should be retrievable
      const stored = await storage.get(`oauth:state:${result.value.state}`);
      expect(stored).toBeTruthy();
    });

    it('createAuthorizationState_SetsExpirationTime', async () => {
      // Arrange
      const now = Date.now();

      // Act
      const result = await createAuthorizationState(storage, undefined, clientConfig);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.createdAt).toBeGreaterThanOrEqual(now);
        // Default TTL is 10 minutes (600000ms)
        expect(result.value.expiresAt).toBe(result.value.createdAt + 600000);
      }
    });

    it('createAuthorizationState_CustomTtl_SetsCorrectExpiration', async () => {
      // Arrange
      const customTtlMs = 300000; // 5 minutes

      // Act
      const result = await createAuthorizationState(
        storage,
        { stateTtlMs: customTtlMs },
        clientConfig
      );

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.expiresAt).toBe(result.value.createdAt + customTtlMs);
      }
    });
  });

  describe('retrieveAuthorizationState', () => {
    const clientConfig = {
      redirectUri: 'https://app.example.com/callback',
      scopes: ['openid'] as const,
    };

    it('retrieveAuthorizationState_ValidState_ReturnsState', async () => {
      // Arrange
      const createResult = await createAuthorizationState(storage, undefined, clientConfig);
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;

      // Act
      const result = await retrieveAuthorizationState(storage, createResult.value.state);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.state).toBe(createResult.value.state);
        expect(result.value.pkce.verifier).toBe(createResult.value.pkce.verifier);
      }
    });

    it('retrieveAuthorizationState_NonexistentState_ReturnsError', async () => {
      // Act
      const result = await retrieveAuthorizationState(storage, 'nonexistent');

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('state_not_found');
      }
    });

    it('retrieveAuthorizationState_ExpiredState_ReturnsError', async () => {
      // Arrange
      const createResult = await createAuthorizationState(
        storage,
        { stateTtlMs: 1000 },
        clientConfig
      );
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;

      // Advance time past expiration
      vi.advanceTimersByTime(1500);

      // Act
      const result = await retrieveAuthorizationState(storage, createResult.value.state);

      // Assert - Storage TTL expires the entry first, so we get state_not_found
      // (the state_expired code is only returned if the entry exists but expiresAt has passed)
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('state_not_found');
      }
    });
  });

  describe('consumeAuthorizationState', () => {
    const clientConfig = {
      redirectUri: 'https://app.example.com/callback',
      scopes: ['openid'] as const,
    };

    it('consumeAuthorizationState_ValidState_ReturnsStateAndDeletes', async () => {
      // Arrange
      const createResult = await createAuthorizationState(storage, undefined, clientConfig);
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;

      // Act
      const result = await consumeAuthorizationState(storage, createResult.value.state);

      // Assert - returns state
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.state).toBe(createResult.value.state);
      }

      // Assert - state is deleted (can't retrieve again)
      const secondResult = await retrieveAuthorizationState(storage, createResult.value.state);
      expect(secondResult.isErr()).toBe(true);
    });

    it('consumeAuthorizationState_NonexistentState_ReturnsError', async () => {
      // Act
      const result = await consumeAuthorizationState(storage, 'nonexistent');

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('state_not_found');
      }
    });

    it('consumeAuthorizationState_CalledTwice_SecondCallFails', async () => {
      // Arrange
      const createResult = await createAuthorizationState(storage, undefined, clientConfig);
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;

      // Act - first consume succeeds
      const firstResult = await consumeAuthorizationState(storage, createResult.value.state);
      expect(firstResult.isOk()).toBe(true);

      // Act - second consume fails
      const secondResult = await consumeAuthorizationState(storage, createResult.value.state);

      // Assert
      expect(secondResult.isErr()).toBe(true);
      if (secondResult.isErr()) {
        expect(secondResult.error.code).toBe('state_not_found');
      }
    });
  });

  describe('validateCallbackState', () => {
    const clientConfig = {
      redirectUri: 'https://app.example.com/callback',
      scopes: ['openid'] as const,
    };

    it('validateCallbackState_MatchingStates_ReturnsAuthState', async () => {
      // Arrange
      const createResult = await createAuthorizationState(storage, undefined, clientConfig);
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;
      const state = createResult.value.state;

      // Act
      const result = await validateCallbackState(storage, state, state);

      // Assert
      expect(result.isOk()).toBe(true);
    });

    it('validateCallbackState_MismatchedStates_ReturnsError', async () => {
      // Arrange
      const createResult = await createAuthorizationState(storage, undefined, clientConfig);
      expect(createResult.isOk()).toBe(true);
      if (!createResult.isOk()) return;

      // Act
      const result = await validateCallbackState(storage, createResult.value.state, 'different');

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('state_mismatch');
        expect(result.error.message).toContain('expected');
        expect(result.error.message).toContain('received');
      }
    });

    it('validateCallbackState_NonexistentState_ReturnsError', async () => {
      // Act
      const result = await validateCallbackState(storage, 'nonexistent', 'nonexistent');

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('state_not_found');
      }
    });
  });
});
