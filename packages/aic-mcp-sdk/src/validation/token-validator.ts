import { ok, err, type Result } from 'neverthrow';
import type {
  TokenValidationResult,
  TokenValidationSuccess,
  AuthenticationInfo,
  TokenClaims,
} from '../types.js';
import type { HttpClient } from '../http/types.js';
import type { Cache } from '../cache/types.js';
import type {
  TokenValidator,
  ValidationOptions,
  OidcDiscoveryDocument,
  IntrospectionResponse,
  TokenValidatorConfig,
  JwtValidatorConfig,
} from './types.js';
import { createFetchClient } from '../http/fetch-client.js';
import { createMemoryCache } from '../cache/memory-cache.js';
import { createCachedDiscoveryFetcher, toAuthenticationInfo } from './discovery.js';
import {
  isJwtFormat,
  createJwks,
  verifyJwt,
  validateJwtClaims,
  parseScopes,
  getMissingScopes,
} from './jwt-validation.js';
import {
  createValidationFailure,
  createMissingTokenFailure,
  createIntrospectionError,
} from './errors.js';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 60 * 60 * 1000;

/** Default realm path for AIC */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/**
 * Introspects an opaque token via RFC 7662 endpoint.
 * Uses client credentials to authenticate the introspection request.
 *
 * @param httpClient - HTTP client for making requests
 * @param token - The token to introspect
 * @param introspectionEndpoint - The introspection endpoint URL
 * @param clientId - OAuth client ID
 * @param clientSecret - OAuth client secret
 * @returns Result with introspection response or error
 */
export const introspectToken = async (
  httpClient: HttpClient,
  token: string,
  introspectionEndpoint: string,
  clientId: string,
  clientSecret: string
): Promise<Result<IntrospectionResponse, ReturnType<typeof createIntrospectionError>>> => {
  // Encode client credentials in base64 for Basic auth
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  // Build request body (form-encoded per RFC 7662)
  const body = new URLSearchParams({
    token,
    token_type_hint: 'access_token',
  }).toString();

  const result = await httpClient.text({
    url: introspectionEndpoint,
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });

  if (result.isErr()) {
    return err(
      createIntrospectionError(
        `Introspection request failed: ${result.error.message}`,
        result.error
      )
    );
  }

  try {
    const introspectionResponse = JSON.parse(result.value.body) as IntrospectionResponse;

    // Validate that we got a valid response
    if (typeof introspectionResponse.active !== 'boolean') {
      return err(
        createIntrospectionError('Invalid introspection response: missing "active" field')
      );
    }

    return ok(introspectionResponse);
  } catch (error) {
    return err(createIntrospectionError('Failed to parse introspection response', error));
  }
};

/**
 * Revokes a token via RFC 7009 revocation endpoint.
 * Uses client credentials to authenticate the revocation request.
 *
 * @param httpClient - HTTP client for making requests
 * @param token - The token to revoke
 * @param revocationEndpoint - The revocation endpoint URL
 * @param clientId - OAuth client ID
 * @param clientSecret - OAuth client secret
 * @returns Result indicating success or error
 *
 * @example
 * ```typescript
 * const result = await revokeToken(
 *   httpClient,
 *   'access_token_value',
 *   'https://auth.example.com/revoke',
 *   'client-id',
 *   'client-secret'
 * );
 *
 * if (result.isOk()) {
 *   console.log('Token revoked successfully');
 * } else {
 *   console.error('Revocation failed:', result.error);
 * }
 * ```
 */
export const revokeToken = async (
  httpClient: HttpClient,
  token: string,
  revocationEndpoint: string,
  clientId: string,
  clientSecret: string
): Promise<Result<{ readonly revoked: true }, ReturnType<typeof createIntrospectionError>>> => {
  // Encode client credentials in base64 for Basic auth
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  // Build request body (form-encoded per RFC 7009)
  const body = new URLSearchParams({
    token,
    token_type_hint: 'access_token',
  }).toString();

  const result = await httpClient.text({
    url: revocationEndpoint,
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });

  if (result.isErr()) {
    return err(
      createIntrospectionError(
        `Token revocation request failed: ${result.error.message}`,
        result.error
      )
    );
  }

  // RFC 7009 specifies that the server responds with 200 OK on successful revocation
  // The response body is typically empty or may contain additional information
  if (result.value.status === 200) {
    return ok({ revoked: true });
  }

  return err(
    createIntrospectionError(
      `Token revocation failed with status ${String(result.value.status)}: ${result.value.statusText}`
    )
  );
};

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
  config: JwtValidatorConfig | TokenValidatorConfig,
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(DEFAULT_DISCOVERY_CACHE_TTL_MS)
): TokenValidator => {
  const { amUrl, clientId, realmPath = DEFAULT_REALM_PATH, discoveryCacheTtlMs } = config;

  // Create cached discovery fetcher
  const discoveryFetcher = createCachedDiscoveryFetcher(
    httpClient,
    discoveryCache,
    amUrl,
    realmPath,
    discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  );

  // JWKS instance with URI tracking (jose handles caching internally)
  let jwksInstance:
    | { readonly uri: string; readonly jwks: ReturnType<typeof createJwks> }
    | undefined;

  /**
   * Gets or creates the JWKS instance.
   * Recreates the instance if the JWKS URI has changed (e.g., after key rotation).
   */
  const getJwks = (jwksUri: string): ReturnType<typeof createJwks> => {
    if (jwksInstance?.uri !== jwksUri) {
      jwksInstance = { uri: jwksUri, jwks: createJwks(jwksUri) };
    }
    return jwksInstance.jwks;
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
    // Use clientId as default audience if not specified
    const verifyResult = await verifyJwt(
      token,
      jwks,
      discovery.issuer,
      options.audience ?? clientId,
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

  /**
   * Introspects an opaque token using client credentials.
   * Only available when clientSecret is provided in config.
   */
  const introspectOpaque = async (
    token: string,
    discovery: OidcDiscoveryDocument,
    config: TokenValidatorConfig,
    options: ValidationOptions
  ): Promise<TokenValidationResult> => {
    const clientSecret = config.clientSecret;

    if (!clientSecret) {
      return createValidationFailure(
        {
          code: 'MALFORMED_TOKEN',
          message: 'Opaque token introspection requires clientSecret configuration.',
        },
        toAuthenticationInfo(discovery)
      );
    }

    if (!discovery.introspection_endpoint) {
      return createValidationFailure(
        {
          code: 'MALFORMED_TOKEN',
          message: 'Introspection endpoint not available in discovery document.',
        },
        toAuthenticationInfo(discovery)
      );
    }

    const introspectionResult = await introspectToken(
      httpClient,
      token,
      discovery.introspection_endpoint,
      clientId,
      clientSecret
    );

    if (introspectionResult.isErr()) {
      return createValidationFailure(introspectionResult.error, toAuthenticationInfo(discovery));
    }

    const introspection = introspectionResult.value;

    // Check if token is active
    if (!introspection.active) {
      return createValidationFailure(
        {
          code: 'REVOKED_TOKEN',
          message: 'Token is not active or has been revoked',
        },
        toAuthenticationInfo(discovery)
      );
    }

    // Validate required claims are present in introspection response
    if (introspection.sub === undefined) {
      return createValidationFailure(
        {
          code: 'MALFORMED_TOKEN',
          message: 'Introspection response missing required "sub" claim',
        },
        toAuthenticationInfo(discovery)
      );
    }

    // Use discovery issuer if not in introspection response
    const iss = introspection.iss ?? discovery.issuer;

    // Use clientId as default audience if not in introspection response
    const aud = introspection.aud ?? clientId;

    // exp and iat may not be present for opaque tokens - use current time as fallback
    const now = Math.floor(Date.now() / 1000);
    const exp = introspection.exp ?? now + 3600; // Default 1 hour if not provided
    const iat = introspection.iat ?? now;

    // Build TokenClaims from introspection response
    const claims: TokenClaims = {
      sub: introspection.sub,
      iss,
      aud,
      exp,
      iat,
      ...(introspection.jti !== undefined ? { jti: introspection.jti } : {}),
      ...(introspection.scope !== undefined ? { scope: introspection.scope } : {}),
      ...(introspection.client_id !== undefined ? { client_id: introspection.client_id } : {}),
      // Include act claim for delegation (RFC 8693)
      ...(introspection.act !== undefined ? { act: introspection.act } : {}),
    };

    // Validate scopes if required
    const { requiredScopes = [] } = options;
    if (requiredScopes.length > 0) {
      const presentScopes = parseScopes(claims.scope);
      const missingScopes = getMissingScopes(requiredScopes, presentScopes);

      if (missingScopes.length > 0) {
        return createValidationFailure(
          {
            code: 'INSUFFICIENT_SCOPE',
            message: `Missing required scopes: ${missingScopes.join(', ')}`,
          },
          toAuthenticationInfo(discovery)
        );
      }
    }

    const success: TokenValidationSuccess = {
      valid: true,
      claims,
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
      // For opaque tokens, attempt introspection if clientSecret is available
      return introspectOpaque(token, discovery, config as TokenValidatorConfig, options);
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
