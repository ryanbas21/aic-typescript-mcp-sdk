/**
 * Token client for OAuth 2.0 token endpoint operations.
 *
 * Handles authorization code exchange and token refresh.
 *
 * @packageDocumentation
 */

import type { Result } from 'neverthrow';
import type { Cache } from '../cache/types.js';
import type { HttpClient } from '../http/types.js';
import type { OidcDiscoveryDocument, ValidationError } from '../validation/types.js';
import { createCachedDiscoveryFetcher } from '../validation/discovery.js';
import { createMemoryCache } from '../cache/memory-cache.js';
import { createFetchClient } from '../http/fetch-client.js';
import { parseScopes } from '../validation/scopes.js';
import type {
  TokenAcquisitionConfig,
  TokenAcquisitionError,
  TokenAcquisitionResult,
  TokenResponse,
  TokenSet,
} from './types.js';
import { isConfidentialClient } from './types.js';

/** Default AM realm path */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 3600000;

/**
 * Options for exchanging an authorization code.
 */
export interface CodeExchangeOptions {
  /** The authorization code from the callback */
  readonly code: string;
  /** The PKCE code verifier */
  readonly codeVerifier: string;
  /** The redirect URI used in the authorization request */
  readonly redirectUri: string;
  /** Target resource (RFC 8707) - should match authorization request */
  readonly resource?: string | undefined;
}

/**
 * Options for refreshing a token.
 */
export interface RefreshOptions {
  /** The refresh token */
  readonly refreshToken: string;
  /** Scopes to request (can be subset of original scopes) */
  readonly scopes?: readonly string[];
}

/**
 * Token client interface.
 */
export interface TokenClient {
  /**
   * Exchanges an authorization code for tokens.
   *
   * @param options - Code exchange options
   * @returns Result with tokens or error
   */
  readonly exchangeCode: (options: CodeExchangeOptions) => Promise<TokenAcquisitionResult>;

  /**
   * Refreshes an access token using a refresh token.
   *
   * @param options - Refresh options
   * @returns Result with tokens or error
   */
  readonly refresh: (options: RefreshOptions) => Promise<TokenAcquisitionResult>;

  /**
   * Gets the cached discovery document.
   *
   * @returns Result with discovery document or error
   */
  readonly getDiscovery: () => Promise<Result<OidcDiscoveryDocument, ValidationError>>;
}

/**
 * Converts a TokenAcquisitionError code to match OAuth error responses.
 */
const parseOAuthError = (errorResponse: Record<string, unknown>): TokenAcquisitionError => {
  const error = errorResponse['error'];
  const errorDescription = errorResponse['error_description'];
  const errorUri = errorResponse['error_uri'];

  // Map known OAuth error codes
  const code =
    typeof error === 'string' &&
    [
      'invalid_request',
      'invalid_client',
      'invalid_grant',
      'unauthorized_client',
      'unsupported_grant_type',
      'invalid_scope',
      'access_denied',
      'server_error',
      'temporarily_unavailable',
    ].includes(error)
      ? (error as TokenAcquisitionError['code'])
      : 'invalid_grant';

  return {
    code,
    message:
      typeof errorDescription === 'string' ? errorDescription : `Token error: ${String(error)}`,
    errorDescription: typeof errorDescription === 'string' ? errorDescription : undefined,
    errorUri: typeof errorUri === 'string' ? errorUri : undefined,
  };
};

/**
 * Converts a token response to a TokenSet.
 */
const toTokenSet = (response: TokenResponse, resource?: string): TokenSet => {
  const now = Date.now();
  const expiresAt = now + response.expires_in * 1000;
  const scopes = parseScopes(response.scope);

  const tokenSet: TokenSet = {
    accessToken: response.access_token,
    tokenType: response.token_type === 'DPoP' ? 'DPoP' : 'Bearer',
    expiresAt,
    scopes,
    ...(resource !== undefined ? { resource } : {}),
    ...(response.refresh_token !== undefined ? { refreshToken: response.refresh_token } : {}),
    ...(response.id_token !== undefined ? { idToken: response.id_token } : {}),
  };

  return tokenSet;
};

/**
 * Creates Basic Auth header for confidential clients.
 */
const createBasicAuthHeader = (clientId: string, clientSecret: string): string => {
  const credentials = `${clientId}:${clientSecret}`;
  return `Basic ${btoa(credentials)}`;
};

/**
 * Converts a validation error to acquisition error.
 */
const toDiscoveryError = (error: ValidationError): TokenAcquisitionError => ({
  code: 'discovery_error',
  message: error.message,
  cause: error.cause,
});

/**
 * Creates a token client for OAuth token operations.
 *
 * @param config - Token acquisition configuration
 * @param httpClient - HTTP client (optional)
 * @param discoveryCache - Cache for discovery document (optional)
 * @returns TokenClient instance
 *
 * @example
 * ```typescript
 * const client = createTokenClient({
 *   amUrl: 'https://auth.example.com',
 *   client: {
 *     clientType: 'confidential',
 *     clientId: 'my-app',
 *     clientSecret: 'secret',
 *     redirectUri: 'https://app.example.com/callback',
 *     scopes: ['openid'],
 *   },
 * });
 *
 * // Exchange authorization code
 * const result = await client.exchangeCode({
 *   code: 'auth_code_from_callback',
 *   codeVerifier: 'stored_pkce_verifier',
 *   redirectUri: 'https://app.example.com/callback',
 * });
 *
 * if (result.success) {
 *   console.log('Access token:', result.tokens.accessToken);
 * }
 * ```
 */
export const createTokenClient = (
  config: TokenAcquisitionConfig,
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(
    config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  )
): TokenClient => {
  const realmPath = config.realmPath ?? DEFAULT_REALM_PATH;
  const cacheTtlMs = config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS;

  // Create cached discovery fetcher
  const discoveryFetcher = createCachedDiscoveryFetcher(
    httpClient,
    discoveryCache,
    config.amUrl,
    realmPath,
    cacheTtlMs
  );

  /**
   * Makes a token request to the token endpoint.
   */
  const makeTokenRequest = async (
    tokenEndpoint: string,
    body: Record<string, string>
  ): Promise<TokenAcquisitionResult> => {
    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    // Add client authentication
    if (isConfidentialClient(config.client)) {
      headers['Authorization'] = createBasicAuthHeader(
        config.client.clientId,
        config.client.clientSecret
      );
    } else {
      // Public client includes client_id in body
      body['client_id'] = config.client.clientId;
    }

    // Convert body to URL-encoded string
    const bodyString = new URLSearchParams(body).toString();

    try {
      const response = await httpClient.json<unknown>({
        url: tokenEndpoint,
        method: 'POST',
        headers,
        body: bodyString,
      });

      if (response.isErr()) {
        return {
          success: false,
          error: {
            code: 'network_error',
            message: `Token request failed: ${response.error.message}`,
            cause: response.error,
          },
        };
      }

      const { status, body: responseBody } = response.value;

      // Check for error response
      if (status >= 400) {
        const errorResponse = responseBody as Record<string, unknown>;
        return {
          success: false,
          error: parseOAuthError(errorResponse),
        };
      }

      // Parse successful response
      const tokenResponse = responseBody as TokenResponse;

      // Validate required fields
      if (
        typeof tokenResponse.access_token !== 'string' ||
        typeof tokenResponse.token_type !== 'string' ||
        typeof tokenResponse.expires_in !== 'number'
      ) {
        return {
          success: false,
          error: {
            code: 'invalid_grant',
            message: 'Invalid token response: missing required fields',
          },
        };
      }

      return {
        success: true,
        tokens: toTokenSet(tokenResponse, body['resource']),
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'network_error',
          message: 'Token request failed',
          cause: error,
        },
      };
    }
  };

  const exchangeCode = async (options: CodeExchangeOptions): Promise<TokenAcquisitionResult> => {
    // Fetch discovery document
    const discoveryResult = await discoveryFetcher.fetch();
    if (discoveryResult.isErr()) {
      return {
        success: false,
        error: toDiscoveryError(discoveryResult.error),
      };
    }

    const discovery = discoveryResult.value;

    // Build token request body
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code: options.code,
      redirect_uri: options.redirectUri,
      code_verifier: options.codeVerifier,
    };

    // Add resource parameter if provided (RFC 8707)
    if (options.resource !== undefined) {
      body['resource'] = options.resource;
    }

    return makeTokenRequest(discovery.token_endpoint, body);
  };

  const refresh = async (options: RefreshOptions): Promise<TokenAcquisitionResult> => {
    // Fetch discovery document
    const discoveryResult = await discoveryFetcher.fetch();
    if (discoveryResult.isErr()) {
      return {
        success: false,
        error: toDiscoveryError(discoveryResult.error),
      };
    }

    const discovery = discoveryResult.value;

    // Build token request body
    const body: Record<string, string> = {
      grant_type: 'refresh_token',
      refresh_token: options.refreshToken,
    };

    // Add scope if provided (for downscoping)
    if (options.scopes !== undefined && options.scopes.length > 0) {
      body['scope'] = options.scopes.join(' ');
    }

    return makeTokenRequest(discovery.token_endpoint, body);
  };

  const getDiscovery = (): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
    return discoveryFetcher.fetch();
  };

  return {
    exchangeCode,
    refresh,
    getDiscovery,
  };
};
