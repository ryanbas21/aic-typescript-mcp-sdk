/**
 * PKCE (Proof Key for Code Exchange) implementation per RFC 7636.
 *
 * MCP spec requires S256 challenge method.
 *
 * @packageDocumentation
 */

import { err, ok, type Result } from 'neverthrow';
import type { OidcDiscoveryDocument } from '../validation/types.js';
import type { PkceChallenge, TokenAcquisitionError } from './types.js';

/**
 * Characters allowed in PKCE verifier (unreserved URI characters).
 * Per RFC 7636 Section 4.1: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 */
const VERIFIER_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/**
 * Minimum length for PKCE verifier (RFC 7636 Section 4.1).
 */
const VERIFIER_MIN_LENGTH = 43;

/**
 * Maximum length for PKCE verifier (RFC 7636 Section 4.1).
 */
const VERIFIER_MAX_LENGTH = 128;

/**
 * Default length for generated PKCE verifier.
 * 64 characters provides ~384 bits of entropy.
 */
const VERIFIER_DEFAULT_LENGTH = 64;

/**
 * Generates a cryptographically secure random string for PKCE verifier.
 *
 * @param length - Length of the verifier (default: 64, range: 43-128)
 * @returns A random string suitable for use as a PKCE verifier
 *
 * @example
 * ```typescript
 * const verifier = generatePkceVerifier();
 * // => "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk..."
 * ```
 */
export const generatePkceVerifier = (length: number = VERIFIER_DEFAULT_LENGTH): string => {
  // Clamp length to valid range
  const clampedLength = Math.max(VERIFIER_MIN_LENGTH, Math.min(VERIFIER_MAX_LENGTH, length));

  // Generate random bytes
  const randomValues = new Uint8Array(clampedLength);
  crypto.getRandomValues(randomValues);

  // Map to allowed characters
  let verifier = '';
  for (let i = 0; i < clampedLength; i++) {
    const randomValue = randomValues[i];
    if (randomValue !== undefined) {
      const charIndex = randomValue % VERIFIER_CHARSET.length;
      const char = VERIFIER_CHARSET[charIndex];
      if (char !== undefined) {
        verifier += char;
      }
    }
  }

  return verifier;
};

/**
 * Creates a SHA-256 hash of the input and returns it as base64url-encoded string.
 *
 * @param input - The string to hash
 * @returns Base64url-encoded SHA-256 hash
 */
const sha256Base64Url = async (input: string): Promise<string> => {
  // Encode input as UTF-8
  const encoder = new TextEncoder();
  const data = encoder.encode(input);

  // Hash with SHA-256
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Convert to base64url (no padding)
  const hashArray = new Uint8Array(hashBuffer);
  let base64 = '';
  for (const byte of hashArray) {
    base64 += String.fromCharCode(byte);
  }

  // btoa for base64, then convert to base64url
  return btoa(base64).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * Creates a PKCE challenge from a verifier using S256 method.
 *
 * @param verifier - The PKCE verifier string
 * @returns Result with PkceChallenge or error
 *
 * @example
 * ```typescript
 * const verifier = generatePkceVerifier();
 * const result = await createPkceChallenge(verifier);
 *
 * if (result.isOk()) {
 *   const { challenge, method } = result.value;
 *   // Use challenge and method in authorization request
 * }
 * ```
 */
export const createPkceChallenge = async (
  verifier: string
): Promise<Result<PkceChallenge, TokenAcquisitionError>> => {
  // Validate verifier length
  if (verifier.length < VERIFIER_MIN_LENGTH) {
    return err({
      code: 'pkce_error',
      message: `PKCE verifier must be at least ${String(VERIFIER_MIN_LENGTH)} characters`,
    });
  }

  if (verifier.length > VERIFIER_MAX_LENGTH) {
    return err({
      code: 'pkce_error',
      message: `PKCE verifier must be at most ${String(VERIFIER_MAX_LENGTH)} characters`,
    });
  }

  // Validate verifier contains only allowed characters
  const invalidChars = verifier.split('').filter((char) => !VERIFIER_CHARSET.includes(char));
  if (invalidChars.length > 0) {
    return err({
      code: 'pkce_error',
      message: `PKCE verifier contains invalid characters: ${invalidChars.join(', ')}`,
    });
  }

  try {
    const challenge = await sha256Base64Url(verifier);

    return ok({
      verifier,
      challenge,
      method: 'S256',
    });
  } catch (error) {
    return err({
      code: 'pkce_error',
      message: 'Failed to create PKCE challenge',
      cause: error,
    });
  }
};

/**
 * Validates that a verifier matches a challenge.
 *
 * @param verifier - The original PKCE verifier
 * @param challenge - The challenge to validate against
 * @returns true if the verifier produces the given challenge
 *
 * @example
 * ```typescript
 * const isValid = await validatePkceChallenge(verifier, challenge);
 * ```
 */
export const validatePkceChallenge = async (
  verifier: string,
  challenge: string
): Promise<boolean> => {
  try {
    const computedChallenge = await sha256Base64Url(verifier);
    return computedChallenge === challenge;
  } catch {
    return false;
  }
};

/**
 * Generates a complete PKCE challenge pair (verifier + challenge).
 *
 * @param verifierLength - Length of the verifier (default: 64)
 * @returns Result with PkceChallenge or error
 *
 * @example
 * ```typescript
 * const result = await generatePkceChallengePair();
 *
 * if (result.isOk()) {
 *   const { verifier, challenge, method } = result.value;
 *   // Store verifier securely, send challenge in auth request
 * }
 * ```
 */
export const generatePkceChallengePair = async (
  verifierLength: number = VERIFIER_DEFAULT_LENGTH
): Promise<Result<PkceChallenge, TokenAcquisitionError>> => {
  const verifier = generatePkceVerifier(verifierLength);
  return createPkceChallenge(verifier);
};

/**
 * Result of PKCE support verification.
 */
export interface PkceSupportResult {
  /** Whether PKCE S256 is supported */
  readonly supported: boolean;
  /** The supported methods from the discovery document */
  readonly supportedMethods: readonly string[];
  /** Warning message if PKCE support could not be verified */
  readonly warning?: string | undefined;
}

/**
 * Verifies that an authorization server supports PKCE with S256.
 *
 * Per MCP spec, clients MUST verify `code_challenge_methods_supported`
 * exists in metadata and includes "S256" before using PKCE.
 *
 * @param discovery - The OIDC discovery document
 * @returns Result indicating PKCE support status
 *
 * @example
 * ```typescript
 * const result = verifyPkceSupport(discovery);
 *
 * if (!result.supported) {
 *   if (result.warning) {
 *     console.warn(result.warning);
 *   } else {
 *     throw new Error('Authorization server does not support PKCE S256');
 *   }
 * }
 * ```
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization
 */
export const verifyPkceSupport = (discovery: OidcDiscoveryDocument): PkceSupportResult => {
  const supportedMethods = discovery.code_challenge_methods_supported ?? [];

  // Check if code_challenge_methods_supported is present
  if (discovery.code_challenge_methods_supported === undefined) {
    // Per MCP spec, this field SHOULD be present. If missing, we warn but allow
    // proceeding since many AS implementations support PKCE without advertising it.
    return {
      supported: false,
      supportedMethods: [],
      warning:
        'Authorization server metadata does not include code_challenge_methods_supported. ' +
        'PKCE support cannot be verified. The server may still support PKCE.',
    };
  }

  // Check if S256 is in the supported methods
  const supportsS256 = supportedMethods.includes('S256');

  if (!supportsS256) {
    return {
      supported: false,
      supportedMethods,
    };
  }

  return {
    supported: true,
    supportedMethods,
  };
};

/**
 * Verifies PKCE support and returns an error if not supported.
 *
 * This is a stricter version that returns an error Result instead of a warning.
 * Use this when PKCE support is mandatory (per MCP spec).
 *
 * @param discovery - The OIDC discovery document
 * @returns Result with void on success, or error if PKCE S256 not supported
 *
 * @example
 * ```typescript
 * const result = requirePkceSupport(discovery);
 *
 * if (result.isErr()) {
 *   throw new Error(result.error.message);
 * }
 *
 * // PKCE S256 is supported, proceed with authorization
 * ```
 */
export const requirePkceSupport = (
  discovery: OidcDiscoveryDocument
): Result<void, TokenAcquisitionError> => {
  const support = verifyPkceSupport(discovery);

  if (!support.supported && support.warning === undefined) {
    // Definitely not supported (field exists but doesn't include S256)
    return err({
      code: 'pkce_error',
      message:
        `Authorization server does not support PKCE S256. ` +
        `Supported methods: ${support.supportedMethods.length > 0 ? support.supportedMethods.join(', ') : 'none'}`,
    });
  }

  // Either supported, or we can't verify (warning case) - proceed
  return ok(undefined);
};
