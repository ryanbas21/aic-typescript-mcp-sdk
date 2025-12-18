import { ok, err, type Result } from 'neverthrow';
import { jwtVerify, createRemoteJWKSet, type JWTVerifyResult } from 'jose';
import type { TokenClaims } from '../types.js';
import type { ValidationError, ValidatedJwtClaims, ValidationOptions } from './types.js';
import { mapJoseError } from './errors.js';
import { parseScopes, getMissingScopes } from './scopes.js';

/**
 * Checks if a string appears to be a JWT (3 base64url-encoded parts separated by dots).
 *
 * @param token - The token string to check
 * @returns true if the token has JWT format
 */
export const isJwtFormat = (token: string): boolean => {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }
  // Check that each part is non-empty and contains only base64url characters
  const base64urlRegex = /^[A-Za-z0-9_-]+$/;
  return parts.every((part) => part.length > 0 && base64urlRegex.test(part));
};

/**
 * Creates a JWKS key set from a URI.
 * The jose library handles caching internally.
 *
 * @param jwksUri - The JWKS URI
 * @returns A function that retrieves keys
 */
export const createJwks = (jwksUri: string): ReturnType<typeof createRemoteJWKSet> => {
  return createRemoteJWKSet(new URL(jwksUri));
};

/**
 * Verifies a JWT signature and decodes the payload.
 *
 * @param token - The JWT to verify
 * @param jwks - The JWKS key set from createRemoteJWKSet
 * @param issuer - Expected issuer
 * @param audience - Expected audience (optional)
 * @param clockToleranceSeconds - Clock tolerance for time validation (default: 15s).
 *   Configurable to accommodate clock skew in distributed systems.
 *   Recommended range is 5-30 seconds.
 * @returns Result with verified claims or validation error
 */
export const verifyJwt = async (
  token: string,
  jwks: ReturnType<typeof createRemoteJWKSet>,
  issuer: string,
  audience?: string | readonly string[],
  clockToleranceSeconds = 15
): Promise<Result<ValidatedJwtClaims, ValidationError>> => {
  try {
    // Build options conditionally for exactOptionalPropertyTypes
    const options: Parameters<typeof jwtVerify>[2] = {
      issuer,
      clockTolerance: clockToleranceSeconds,
    };

    if (audience !== undefined) {
      options.audience = audience as string | string[];
    }

    const result: JWTVerifyResult = await jwtVerify(token, jwks, options);

    const payload = result.payload;

    // Validate required claims are present
    if (typeof payload.sub !== 'string') {
      return err({
        code: 'MALFORMED_TOKEN',
        message: 'Token is missing required "sub" claim',
      });
    }
    if (typeof payload.iss !== 'string') {
      return err({
        code: 'MALFORMED_TOKEN',
        message: 'Token is missing required "iss" claim',
      });
    }
    if (payload.aud === undefined) {
      return err({
        code: 'MALFORMED_TOKEN',
        message: 'Token is missing required "aud" claim',
      });
    }
    if (typeof payload.exp !== 'number') {
      return err({
        code: 'MALFORMED_TOKEN',
        message: 'Token is missing required "exp" claim',
      });
    }
    if (typeof payload.iat !== 'number') {
      return err({
        code: 'MALFORMED_TOKEN',
        message: 'Token is missing required "iat" claim',
      });
    }

    // Normalize aud to mutable array for ValidatedJwtClaims
    const normalizedAud: string | string[] = Array.isArray(payload.aud)
      ? [...payload.aud]
      : payload.aud;

    const validatedClaims: ValidatedJwtClaims = {
      sub: payload.sub,
      iss: payload.iss,
      aud: normalizedAud,
      exp: payload.exp,
      iat: payload.iat,
    };

    // Copy optional standard claims
    if (payload.jti !== undefined) {
      (validatedClaims as Record<string, unknown>)['jti'] = payload.jti;
    }
    if (payload.nbf !== undefined) {
      (validatedClaims as Record<string, unknown>)['nbf'] = payload.nbf;
    }

    // Copy scope and client_id if present (access via index signature)
    const scope = payload['scope'];
    if (scope !== undefined) {
      (validatedClaims as Record<string, unknown>)['scope'] = scope;
    }
    const clientId = payload['client_id'];
    if (clientId !== undefined) {
      (validatedClaims as Record<string, unknown>)['client_id'] = clientId;
    }

    return ok(validatedClaims);
  } catch (error) {
    return err(mapJoseError(error));
  }
};

/**
 * Checks if all required scopes are present in the provided scopes.
 *
 * @param requiredScopes - Scopes that must be present
 * @param presentScopes - Scopes that are actually present
 * @returns Result with present scopes or error with missing scopes
 */
export const validateScopes = (
  requiredScopes: readonly string[],
  presentScopes: readonly string[]
): Result<readonly string[], ValidationError> => {
  const missingScopes = getMissingScopes(requiredScopes, presentScopes);

  if (missingScopes.length > 0) {
    return err({
      code: 'INSUFFICIENT_SCOPE',
      message: `Missing required scopes: ${missingScopes.join(', ')}`,
    });
  }

  return ok(presentScopes);
};

// Re-export for external use
export { parseScopes, getMissingScopes } from './scopes.js';

/**
 * Converts ValidatedJwtClaims to TokenClaims.
 *
 * @param claims - The validated JWT claims
 * @returns TokenClaims object
 */
export const toTokenClaims = (claims: ValidatedJwtClaims): TokenClaims => {
  // Start with required fields
  const base: TokenClaims = {
    sub: claims.sub,
    iss: claims.iss,
    aud: claims.aud,
    exp: claims.exp,
    iat: claims.iat,
  };

  // Spread additional custom claims first, then override with known optional fields
  const result: Record<string, unknown> = { ...base };

  // Copy all other claims from the original
  for (const [key, value] of Object.entries(claims)) {
    if (!['sub', 'iss', 'aud', 'exp', 'iat'].includes(key) && value !== undefined) {
      result[key] = value;
    }
  }

  return result as TokenClaims;
};

/**
 * Validates JWT claims against provided options.
 *
 * @param claims - The validated JWT claims
 * @param options - Validation options
 * @returns Result with TokenClaims or validation error
 */
export const validateJwtClaims = (
  claims: ValidatedJwtClaims,
  options: ValidationOptions = {}
): Result<TokenClaims, ValidationError> => {
  const { requiredScopes = [] } = options;

  // Validate scopes if required
  if (requiredScopes.length > 0) {
    const presentScopes = parseScopes(claims.scope);
    const scopeResult = validateScopes(requiredScopes, presentScopes);
    if (scopeResult.isErr()) {
      return err(scopeResult.error);
    }
  }

  return ok(toTokenClaims(claims));
};
