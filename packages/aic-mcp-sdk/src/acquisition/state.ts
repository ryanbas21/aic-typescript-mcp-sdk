/**
 * Authorization state management for OAuth flows.
 *
 * Handles state parameter generation and validation for CSRF protection.
 *
 * @packageDocumentation
 */

import { err, ok, type Result } from 'neverthrow';
import type { SecureStorage } from '../storage/types.js';
import { generatePkceChallengePair } from './pkce.js';
import type {
  AuthorizationState,
  AuthorizationUrlOptions,
  PkceChallenge,
  TokenAcquisitionError,
} from './types.js';

/**
 * Characters allowed in state parameter.
 * Using alphanumeric characters for URL-safety.
 */
const STATE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Default length for state parameter.
 * 32 characters provides ~190 bits of entropy.
 */
const STATE_DEFAULT_LENGTH = 32;

/**
 * Default TTL for authorization state: 10 minutes.
 */
const STATE_DEFAULT_TTL_MS = 10 * 60 * 1000;

/**
 * Storage key prefix for authorization state.
 */
const STATE_KEY_PREFIX = 'oauth:state:';

/**
 * Generates a cryptographically secure state parameter.
 *
 * @param length - Length of the state string (default: 32)
 * @returns A random string suitable for use as OAuth state parameter
 *
 * @example
 * ```typescript
 * const state = generateState();
 * // => "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"
 * ```
 */
export const generateState = (length: number = STATE_DEFAULT_LENGTH): string => {
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);

  let state = '';
  for (let i = 0; i < length; i++) {
    const randomValue = randomValues[i];
    if (randomValue !== undefined) {
      const charIndex = randomValue % STATE_CHARSET.length;
      const char = STATE_CHARSET[charIndex];
      if (char !== undefined) {
        state += char;
      }
    }
  }

  return state;
};

/**
 * Generates a nonce for OpenID Connect.
 *
 * @param length - Length of the nonce string (default: 32)
 * @returns A random string suitable for use as OIDC nonce
 */
export const generateNonce = (length: number = STATE_DEFAULT_LENGTH): string => {
  return generateState(length);
};

/**
 * Creates and stores an authorization state.
 *
 * @param storage - Secure storage for persisting state
 * @param options - Authorization options
 * @param clientConfig - Client configuration defaults
 * @returns Result with the created authorization state
 *
 * @example
 * ```typescript
 * const result = await createAuthorizationState(storage, {
 *   scopes: ['openid', 'profile'],
 *   resource: 'https://api.example.com',
 * }, {
 *   redirectUri: 'https://app.example.com/callback',
 *   scopes: ['openid'],
 * });
 *
 * if (result.isOk()) {
 *   // Use result.value.state in authorization URL
 * }
 * ```
 */
export const createAuthorizationState = async (
  storage: SecureStorage,
  options: AuthorizationUrlOptions | undefined,
  clientConfig: {
    readonly redirectUri: string;
    readonly scopes: readonly string[];
  }
): Promise<Result<AuthorizationState, TokenAcquisitionError>> => {
  // Generate state and nonce
  const state = options?.state ?? generateState();
  const nonce = options?.nonce ?? generateNonce();

  // Generate PKCE challenge pair
  const pkceResult = await generatePkceChallengePair();
  if (pkceResult.isErr()) {
    return err(pkceResult.error);
  }

  const pkce = pkceResult.value;
  const now = Date.now();
  const ttlMs = options?.stateTtlMs ?? STATE_DEFAULT_TTL_MS;

  const authState: AuthorizationState = {
    state,
    pkce,
    redirectUri: clientConfig.redirectUri,
    scopes: options?.scopes ?? clientConfig.scopes,
    resource: options?.resource,
    nonce,
    createdAt: now,
    expiresAt: now + ttlMs,
  };

  // Store the state
  try {
    await storage.set(STATE_KEY_PREFIX + state, JSON.stringify(authState), ttlMs);
    return ok(authState);
  } catch (error) {
    return err({
      code: 'pkce_error',
      message: 'Failed to store authorization state',
      cause: error,
    });
  }
};

/**
 * Retrieves and validates an authorization state.
 *
 * @param storage - Secure storage containing the state
 * @param state - The state parameter from the callback
 * @returns Result with the authorization state or error
 *
 * @example
 * ```typescript
 * const result = await retrieveAuthorizationState(storage, callbackState);
 *
 * if (result.isOk()) {
 *   const { pkce, scopes } = result.value;
 *   // Use pkce.verifier for token exchange
 * }
 * ```
 */
export const retrieveAuthorizationState = async (
  storage: SecureStorage,
  state: string
): Promise<Result<AuthorizationState, TokenAcquisitionError>> => {
  try {
    const stored = await storage.get(STATE_KEY_PREFIX + state);

    if (stored === undefined) {
      return err({
        code: 'state_not_found',
        message: 'Authorization state not found. It may have expired or was never created.',
      });
    }

    const authState = JSON.parse(stored) as AuthorizationState;

    // Validate expiration
    if (Date.now() > authState.expiresAt) {
      // Clean up expired state
      await storage.delete(STATE_KEY_PREFIX + state);

      return err({
        code: 'state_expired',
        message: 'Authorization state has expired. Please restart the authorization flow.',
      });
    }

    return ok(authState);
  } catch (error) {
    return err({
      code: 'pkce_error',
      message: 'Failed to retrieve authorization state',
      cause: error,
    });
  }
};

/**
 * Consumes an authorization state (retrieve and delete).
 *
 * This should be used during callback handling to ensure
 * each state can only be used once.
 *
 * @param storage - Secure storage containing the state
 * @param state - The state parameter from the callback
 * @returns Result with the authorization state or error
 *
 * @example
 * ```typescript
 * // In callback handler:
 * const result = await consumeAuthorizationState(storage, callbackState);
 *
 * if (result.isOk()) {
 *   // State is now deleted, can only be used once
 *   const { pkce } = result.value;
 *   await exchangeCode(code, pkce.verifier);
 * }
 * ```
 */
export const consumeAuthorizationState = async (
  storage: SecureStorage,
  state: string
): Promise<Result<AuthorizationState, TokenAcquisitionError>> => {
  const result = await retrieveAuthorizationState(storage, state);

  if (result.isOk()) {
    // Delete state after successful retrieval (one-time use)
    await storage.delete(STATE_KEY_PREFIX + state);
  }

  return result;
};

/**
 * Validates that a callback state matches a stored state.
 *
 * @param storage - Secure storage containing the state
 * @param expectedState - The expected state value
 * @param receivedState - The state received in callback
 * @returns Result with the authorization state or error
 */
export const validateCallbackState = async (
  storage: SecureStorage,
  expectedState: string,
  receivedState: string
): Promise<Result<AuthorizationState, TokenAcquisitionError>> => {
  // First check if states match
  if (expectedState !== receivedState) {
    return err({
      code: 'state_mismatch',
      message: `State mismatch: expected "${expectedState}", received "${receivedState}"`,
    });
  }

  // Then retrieve and validate the state
  return retrieveAuthorizationState(storage, receivedState);
};

/**
 * Serializes a PKCE challenge for storage.
 */
export const serializePkceChallenge = (pkce: PkceChallenge): string => {
  return JSON.stringify(pkce);
};

/**
 * Deserializes a PKCE challenge from storage.
 */
export const deserializePkceChallenge = (
  serialized: string
): Result<PkceChallenge, TokenAcquisitionError> => {
  try {
    const parsed: unknown = JSON.parse(serialized);

    // Type guard for PkceChallenge structure
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('verifier' in parsed) ||
      !('challenge' in parsed) ||
      !('method' in parsed) ||
      typeof (parsed as Record<string, unknown>)['verifier'] !== 'string' ||
      typeof (parsed as Record<string, unknown>)['challenge'] !== 'string' ||
      (parsed as Record<string, unknown>)['method'] !== 'S256'
    ) {
      return err({
        code: 'pkce_error',
        message: 'Invalid PKCE challenge format',
      });
    }

    return ok(parsed as PkceChallenge);
  } catch (error) {
    return err({
      code: 'pkce_error',
      message: 'Failed to deserialize PKCE challenge',
      cause: error,
    });
  }
};
