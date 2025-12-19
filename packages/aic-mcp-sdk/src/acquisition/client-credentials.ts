/**
 * Client credentials flow for service-to-service authentication.
 *
 * Used when the MCP server needs its own token (not on behalf of a user).
 *
 * @packageDocumentation
 */

import type { Cache } from '../cache/types.js';
import type { HttpClient } from '../http/types.js';
import type { OidcDiscoveryDocument, ValidationError } from '../validation/types.js';
import { createCachedDiscoveryFetcher } from '../validation/discovery.js';
import { createMemoryCache } from '../cache/memory-cache.js';
import { createFetchClient } from '../http/fetch-client.js';
import { parseScopes } from '../validation/scopes.js';
import type {
  ClientCredentialsOptions,
  ConfidentialClientConfig,
  TokenAcquisitionConfig,
  TokenAcquisitionError,
  TokenAcquisitionResult,
  TokenResponse,
  TokenSet,
} from './types.js';

/** Default AM realm path */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 3600000;

/**
 * Configuration for client credentials acquirer.
 * Requires confidential client configuration.
 */
export interface ClientCredentialsConfig extends Omit<TokenAcquisitionConfig, 'client'> {
  readonly client: ConfidentialClientConfig;
}

/**
 * Client credentials acquirer interface.
 */
export interface ClientCredentialsAcquirer {
  /**
   * Acquires a token using client credentials grant.
   *
   * @param options - Client credentials options
   * @returns Result with tokens or error
   */
  readonly acquire: (options?: ClientCredentialsOptions) => Promise<TokenAcquisitionResult>;
}

/**
 * Creates Basic Auth header for confidential clients.
 */
const createBasicAuthHeader = (clientId: string, clientSecret: string): string => {
  const credentials = `${clientId}:${clientSecret}`;
  return `Basic ${btoa(credentials)}`;
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
 * Converts a validation error to acquisition error.
 */
const toDiscoveryError = (error: ValidationError): TokenAcquisitionError => ({
  code: 'discovery_error',
  message: error.message,
  cause: error.cause,
});

/**
 * Parses OAuth error response.
 */
const parseOAuthError = (errorResponse: Record<string, unknown>): TokenAcquisitionError => {
  const error = errorResponse['error'];
  const errorDescription = errorResponse['error_description'];
  const errorUri = errorResponse['error_uri'];

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
      : 'invalid_client';

  return {
    code,
    message:
      typeof errorDescription === 'string' ? errorDescription : `Token error: ${String(error)}`,
    errorDescription: typeof errorDescription === 'string' ? errorDescription : undefined,
    errorUri: typeof errorUri === 'string' ? errorUri : undefined,
  };
};

/**
 * Creates a client credentials token acquirer.
 *
 * @param config - Client credentials configuration (requires confidential client)
 * @param httpClient - HTTP client (optional)
 * @param discoveryCache - Cache for discovery document (optional)
 * @returns ClientCredentialsAcquirer instance
 *
 * @example
 * ```typescript
 * const acquirer = createClientCredentialsAcquirer({
 *   amUrl: 'https://auth.example.com',
 *   client: {
 *     clientType: 'confidential',
 *     clientId: 'my-service',
 *     clientSecret: 'secret',
 *     redirectUri: '', // Not used for client credentials
 *     scopes: ['api:read', 'api:write'],
 *   },
 * });
 *
 * const result = await acquirer.acquire({
 *   scopes: ['api:read'],
 *   resource: 'https://api.example.com',
 * });
 *
 * if (result.success) {
 *   console.log('Service token:', result.tokens.accessToken);
 * }
 * ```
 */
export const createClientCredentialsAcquirer = (
  config: ClientCredentialsConfig,
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(
    config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  )
): ClientCredentialsAcquirer => {
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

  const acquire = async (options?: ClientCredentialsOptions): Promise<TokenAcquisitionResult> => {
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
      grant_type: 'client_credentials',
    };

    // Add scope if provided, otherwise use default client scopes
    const scopes = options?.scopes ?? config.client.scopes;
    if (scopes.length > 0) {
      body['scope'] = scopes.join(' ');
    }

    // Add resource parameter if provided (RFC 8707)
    if (options?.resource !== undefined) {
      body['resource'] = options.resource;
    }

    // Build headers with Basic Auth
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: createBasicAuthHeader(config.client.clientId, config.client.clientSecret),
    };

    // Convert body to URL-encoded string
    const bodyString = new URLSearchParams(body).toString();

    try {
      const response = await httpClient.json<unknown>({
        url: discovery.token_endpoint,
        method: 'POST',
        headers,
        body: bodyString,
      });

      if (response.isErr()) {
        return {
          success: false,
          error: {
            code: 'network_error',
            message: `Client credentials request failed: ${response.error.message}`,
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
        tokens: toTokenSet(tokenResponse, options?.resource),
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'network_error',
          message: 'Client credentials request failed',
          cause: error,
        },
      };
    }
  };

  return { acquire };
};
