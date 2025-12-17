import type {
  TokenValidationResult,
  TokenValidationSuccess,
  AuthenticationInfo,
} from '../types.js';
import type { HttpClient } from '../http/types.js';
import type { Cache } from '../cache/types.js';
import type {
  TokenValidator,
  JwtValidatorConfig,
  ValidationOptions,
  OidcDiscoveryDocument,
} from './types.js';
import { createFetchClient } from '../http/fetch-client.js';
import { createMemoryCache } from '../cache/memory-cache.js';
import { createCachedDiscoveryFetcher, toAuthenticationInfo } from './discovery.js';
import { isJwtFormat, createJwks, verifyJwt, validateJwtClaims } from './jwt-validation.js';
import { createValidationFailure, createMissingTokenFailure } from './errors.js';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 60 * 60 * 1000;

/** Default realm path for AIC */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/**
 * Creates a token validator for AIC.
 *
 * @param config - Validator configuration
 * @param httpClient - Optional HTTP client (default: createFetchClient())
 * @param discoveryCache - Optional cache for discovery document (default: createMemoryCache())
 * @returns A TokenValidator instance
 *
 * @example
 * ```typescript
 * const validator = createTokenValidator({
 *   amUrl: 'https://auth.example.com',
 *   clientId: 'my-client-id',
 * });
 *
 * const result = await validator.validate(token, { requiredScopes: ['read', 'write'] });
 *
 * if (result.valid) {
 *   console.log('User:', result.claims.sub);
 * } else {
 *   console.log('Error:', result.error, result.message);
 * }
 * ```
 */
export const createTokenValidator = (
  config: JwtValidatorConfig,
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(DEFAULT_DISCOVERY_CACHE_TTL_MS)
): TokenValidator => {
  const { amUrl, realmPath = DEFAULT_REALM_PATH, discoveryCacheTtlMs } = config;

  // Create cached discovery fetcher
  const discoveryFetcher = createCachedDiscoveryFetcher(
    httpClient,
    discoveryCache,
    amUrl,
    realmPath,
    discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  );

  // JWKS instance (jose handles caching internally)
  let jwksInstance: ReturnType<typeof createJwks> | undefined;

  /**
   * Gets or creates the JWKS instance.
   */
  const getJwks = (jwksUri: string): ReturnType<typeof createJwks> => {
    jwksInstance ??= createJwks(jwksUri);
    return jwksInstance;
  };

  /**
   * Validates a JWT token.
   */
  const validateJwt = async (
    token: string,
    discovery: OidcDiscoveryDocument,
    options: ValidationOptions
  ): Promise<TokenValidationResult> => {
    const jwks = getJwks(discovery.jwks_uri);

    // Verify JWT signature and decode payload
    const verifyResult = await verifyJwt(
      token,
      jwks,
      discovery.issuer,
      options.audience,
      options.clockToleranceSeconds
    );

    if (verifyResult.isErr()) {
      return createValidationFailure(verifyResult.error, toAuthenticationInfo(discovery));
    }

    // Validate claims against options
    const claimsResult = validateJwtClaims(verifyResult.value, options);

    if (claimsResult.isErr()) {
      return createValidationFailure(claimsResult.error, toAuthenticationInfo(discovery));
    }

    const success: TokenValidationSuccess = {
      valid: true,
      claims: claimsResult.value,
      accessToken: token,
    };

    return success;
  };

  const validate = async (
    token: string | undefined,
    options: ValidationOptions = {}
  ): Promise<TokenValidationResult> => {
    // Check for missing token
    if (!token || token.trim().length === 0) {
      // Try to get auth info for the response
      const discoveryResult = await discoveryFetcher.fetch();
      const authInfo = discoveryResult.isOk()
        ? toAuthenticationInfo(discoveryResult.value)
        : undefined;
      return createMissingTokenFailure(authInfo);
    }

    // Fetch discovery document
    const discoveryResult = await discoveryFetcher.fetch();

    if (discoveryResult.isErr()) {
      return createValidationFailure(discoveryResult.error);
    }

    const discovery = discoveryResult.value;

    // Check if token is JWT format
    if (!isJwtFormat(token)) {
      // TODO: Opaque token introspection (RFC 7662) not yet implemented
      return createValidationFailure(
        {
          code: 'MALFORMED_TOKEN',
          message: 'Token is not a valid JWT. Opaque token introspection is not yet supported.',
        },
        toAuthenticationInfo(discovery)
      );
    }

    return validateJwt(token, discovery, options);
  };

  const getAuthenticationInfo = async (): Promise<AuthenticationInfo | undefined> => {
    const discoveryResult = await discoveryFetcher.fetch();

    if (discoveryResult.isErr()) {
      return undefined;
    }

    return toAuthenticationInfo(discoveryResult.value);
  };

  const refreshCache = async (): Promise<void> => {
    // Clear discovery cache
    discoveryFetcher.clear();

    // Clear JWKS instance (jose will refetch on next use)
    jwksInstance = undefined;

    // Pre-fetch discovery document
    await discoveryFetcher.fetch();
  };

  return {
    validate,
    getAuthenticationInfo,
    refreshCache,
  };
};
