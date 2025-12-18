import type { TokenValidationError, TokenValidationFailure, AuthenticationInfo } from '../types.js';
import type { ValidationError } from './types.js';

/**
 * Maps internal validation error codes to public TokenValidationError codes.
 */
const errorCodeMapping: Record<ValidationError['code'], TokenValidationError> = {
  MISSING_TOKEN: 'MISSING_TOKEN',
  MALFORMED_TOKEN: 'MALFORMED_TOKEN',
  EXPIRED_TOKEN: 'EXPIRED_TOKEN',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  INVALID_ISSUER: 'INVALID_ISSUER',
  INVALID_AUDIENCE: 'INVALID_AUDIENCE',
  REVOKED_TOKEN: 'REVOKED_TOKEN',
  INSUFFICIENT_SCOPE: 'INSUFFICIENT_SCOPE',
  DISCOVERY_ERROR: 'VALIDATION_ERROR',
  JWKS_ERROR: 'VALIDATION_ERROR',
  INTROSPECTION_ERROR: 'VALIDATION_ERROR',
  NETWORK_ERROR: 'VALIDATION_ERROR',
};

/**
 * Default error messages for each error code.
 */
const defaultMessages: Record<TokenValidationError, string> = {
  MISSING_TOKEN: 'No access token provided',
  MALFORMED_TOKEN: 'Token is malformed or invalid',
  EXPIRED_TOKEN: 'Token has expired',
  INVALID_SIGNATURE: 'Token signature is invalid',
  INVALID_ISSUER: 'Token issuer is not trusted',
  INVALID_AUDIENCE: 'Token audience does not match',
  REVOKED_TOKEN: 'Token has been revoked',
  INSUFFICIENT_SCOPE: 'Token does not have required scopes',
  VALIDATION_ERROR: 'Token validation failed',
};

/**
 * Creates a TokenValidationFailure from a ValidationError.
 *
 * @param error - The internal validation error
 * @param authInfo - Optional authentication info for 401 responses
 * @returns A TokenValidationFailure object
 */
export const createValidationFailure = (
  error: ValidationError,
  authInfo?: AuthenticationInfo
): TokenValidationFailure => {
  const publicCode = errorCodeMapping[error.code];
  const base = {
    valid: false as const,
    error: publicCode,
    message: error.message || defaultMessages[publicCode],
  };

  if (authInfo !== undefined) {
    return { ...base, authenticationInfo: authInfo };
  }

  return base;
};

/**
 * Creates a TokenValidationFailure for missing token.
 *
 * @param authInfo - Optional authentication info for 401 responses
 * @returns A TokenValidationFailure object
 */
export const createMissingTokenFailure = (
  authInfo?: AuthenticationInfo
): TokenValidationFailure => {
  const base = {
    valid: false as const,
    error: 'MISSING_TOKEN' as const,
    message: defaultMessages.MISSING_TOKEN,
  };

  if (authInfo !== undefined) {
    return { ...base, authenticationInfo: authInfo };
  }

  return base;
};

/**
 * Creates a TokenValidationFailure for insufficient scopes.
 *
 * @param requiredScopes - The scopes that were required
 * @param presentScopes - The scopes that were present
 * @param authInfo - Optional authentication info for 401 responses
 * @returns A TokenValidationFailure object
 */
export const createInsufficientScopeFailure = (
  requiredScopes: readonly string[],
  presentScopes: readonly string[],
  authInfo?: AuthenticationInfo
): TokenValidationFailure => {
  const base = {
    valid: false as const,
    error: 'INSUFFICIENT_SCOPE' as const,
    message: `Missing required scopes: ${requiredScopes.filter((s) => !presentScopes.includes(s)).join(', ')}`,
  };

  if (authInfo !== undefined) {
    return { ...base, authenticationInfo: authInfo };
  }

  return base;
};

/**
 * Maps jose library errors to ValidationError.
 *
 * @param error - The error from jose
 * @returns A ValidationError object
 */
export const mapJoseError = (error: unknown): ValidationError => {
  if (!(error instanceof Error)) {
    return {
      code: 'MALFORMED_TOKEN',
      message: 'Unknown token validation error',
      cause: error,
    };
  }

  const name = error.name;
  const message = error.message;

  // jose error types
  switch (name) {
    case 'JWTExpired':
      return { code: 'EXPIRED_TOKEN', message: 'Token has expired', cause: error };
    case 'JWTClaimValidationFailed':
      if (message.includes('iss')) {
        return { code: 'INVALID_ISSUER', message: 'Token issuer is invalid', cause: error };
      }
      if (message.includes('aud')) {
        return { code: 'INVALID_AUDIENCE', message: 'Token audience is invalid', cause: error };
      }
      return { code: 'MALFORMED_TOKEN', message, cause: error };
    case 'JWSSignatureVerificationFailed':
      return {
        code: 'INVALID_SIGNATURE',
        message: 'Token signature verification failed',
        cause: error,
      };
    case 'JWSInvalid':
    case 'JWTInvalid':
      return { code: 'MALFORMED_TOKEN', message: 'Token format is invalid', cause: error };
    default:
      return {
        code: 'MALFORMED_TOKEN',
        message: message || 'Token validation failed',
        cause: error,
      };
  }
};

/**
 * Creates a ValidationError for network failures.
 *
 * @param message - Error message
 * @param cause - Original error
 * @returns A ValidationError object
 */
export const createNetworkError = (message: string, cause?: unknown): ValidationError => ({
  code: 'NETWORK_ERROR',
  message,
  cause,
});

/**
 * Creates a ValidationError for discovery document failures.
 *
 * @param message - Error message
 * @param cause - Original error
 * @returns A ValidationError object
 */
export const createDiscoveryError = (message: string, cause?: unknown): ValidationError => ({
  code: 'DISCOVERY_ERROR',
  message,
  cause,
});

/**
 * Creates a ValidationError for JWKS failures.
 *
 * @param message - Error message
 * @param cause - Original error
 * @returns A ValidationError object
 */
export const createJwksError = (message: string, cause?: unknown): ValidationError => ({
  code: 'JWKS_ERROR',
  message,
  cause,
});

/**
 * Creates a ValidationError for introspection failures.
 *
 * @param message - Error message
 * @param cause - Original error
 * @returns A ValidationError object
 */
export const createIntrospectionError = (message: string, cause?: unknown): ValidationError => ({
  code: 'INTROSPECTION_ERROR',
  message,
  cause,
});
