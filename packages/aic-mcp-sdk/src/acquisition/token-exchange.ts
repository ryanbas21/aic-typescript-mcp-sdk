/**
 * Token exchange implementation per RFC 8693.
 *
 * Used for identity delegation when the MCP server needs to call
 * downstream services on behalf of a user.
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
  ConfidentialClientConfig,
  SubjectTokenType,
  TokenAcquisitionConfig,
  TokenAcquisitionError,
  TokenExchangeRequest,
  TokenExchangeResponse,
  TokenExchangeResult,
  TokenResponse,
} from './types.js';

/** Default AM realm path */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 3600000;

/** Token exchange grant type per RFC 8693 */
const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/**
 * Configuration for token exchanger.
 * Requires confidential client configuration.
 */
export interface TokenExchangeConfig extends Omit<TokenAcquisitionConfig, 'client'> {
  readonly client: ConfidentialClientConfig;
}

/**
 * Token exchanger interface.
 */
export interface TokenExchanger {
  /**
   * Exchanges a token for a new token.
   *
   * @param request - Token exchange request
   * @returns Result with exchanged tokens or error
   */
  readonly exchange: (request: TokenExchangeRequest) => Promise<TokenExchangeResult>;
}

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
      'unsupported_token_type',
    ].includes(error)
      ? (error as TokenAcquisitionError['code'])
      : 'invalid_grant';

  return {
    code,
    message:
      typeof errorDescription === 'string'
        ? errorDescription
        : `Token exchange error: ${String(error)}`,
    errorDescription: typeof errorDescription === 'string' ? errorDescription : undefined,
    errorUri: typeof errorUri === 'string' ? errorUri : undefined,
  };
};

/**
 * Converts a token exchange response to TokenExchangeResponse.
 */
const toTokenExchangeResponse = (
  response: TokenResponse & { readonly issued_token_type?: string },
  request: TokenExchangeRequest
): TokenExchangeResponse => {
  const now = Date.now();
  const expiresAt = now + response.expires_in * 1000;
  const scopes = parseScopes(response.scope);

  // Determine issued token type
  const issuedTokenType: SubjectTokenType =
    typeof response.issued_token_type === 'string' &&
    [
      'urn:ietf:params:oauth:token-type:access_token',
      'urn:ietf:params:oauth:token-type:refresh_token',
      'urn:ietf:params:oauth:token-type:id_token',
      'urn:ietf:params:oauth:token-type:jwt',
    ].includes(response.issued_token_type)
      ? (response.issued_token_type as SubjectTokenType)
      : 'urn:ietf:params:oauth:token-type:access_token';

  return {
    accessToken: response.access_token,
    tokenType: response.token_type === 'DPoP' ? 'DPoP' : 'Bearer',
    expiresAt,
    scopes,
    issuedTokenType,
    ...(request.resource !== undefined ? { resource: request.resource } : {}),
    ...(response.refresh_token !== undefined ? { refreshToken: response.refresh_token } : {}),
    ...(response.id_token !== undefined ? { idToken: response.id_token } : {}),
  };
};

/**
 * Creates a token exchanger for RFC 8693 token exchange.
 *
 * Token exchange is used for identity delegation, allowing an MCP server
 * to call downstream services on behalf of a user while preserving
 * identity context.
 *
 * @param config - Token exchange configuration (requires confidential client)
 * @param httpClient - HTTP client (optional)
 * @param discoveryCache - Cache for discovery document (optional)
 * @returns TokenExchanger instance
 *
 * @example
 * ```typescript
 * const exchanger = createTokenExchanger({
 *   amUrl: 'https://auth.example.com',
 *   client: {
 *     clientType: 'confidential',
 *     clientId: 'my-mcp-server',
 *     clientSecret: 'secret',
 *     redirectUri: '',
 *     scopes: [],
 *   },
 * });
 *
 * // Exchange user's token for downstream API token
 * const result = await exchanger.exchange({
 *   subjectToken: userAccessToken,
 *   subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
 *   audience: 'downstream-api',
 *   scope: 'api:read api:write',
 * });
 *
 * if (result.success) {
 *   // Use exchanged token for downstream call
 *   await callDownstreamApi(result.tokens.accessToken);
 * }
 * ```
 */
export const createTokenExchanger = (
  config: TokenExchangeConfig,
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(
    config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  )
): TokenExchanger => {
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

  const exchange = async (request: TokenExchangeRequest): Promise<TokenExchangeResult> => {
    // Fetch discovery document
    const discoveryResult = await discoveryFetcher.fetch();
    if (discoveryResult.isErr()) {
      return {
        success: false,
        error: toDiscoveryError(discoveryResult.error),
      };
    }

    const discovery = discoveryResult.value;

    // Build token exchange request body per RFC 8693
    const body: Record<string, string> = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: request.subjectToken,
      subject_token_type: request.subjectTokenType,
    };

    // Add optional parameters
    if (request.requestedTokenType !== undefined) {
      body['requested_token_type'] = request.requestedTokenType;
    }

    if (request.audience !== undefined) {
      body['audience'] = request.audience;
    }

    if (request.scope !== undefined) {
      body['scope'] = request.scope;
    }

    if (request.resource !== undefined) {
      body['resource'] = request.resource;
    }

    // Add actor token for delegation scenarios
    if (request.actorToken !== undefined) {
      body['actor_token'] = request.actorToken;
      if (request.actorTokenType !== undefined) {
        body['actor_token_type'] = request.actorTokenType;
      }
    }

    // Build headers with Basic Auth
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: createBasicAuthHeader(config.client.clientId, config.client.clientSecret),
    };

    // Convert body to URL-encoded string
    const bodyString = new URLSearchParams(body).toString();

    // Log token exchange request details for debugging
    console.error('[token-exchange] Token endpoint:', discovery.token_endpoint);
    console.error('[token-exchange] Subject token:', request.subjectToken);
    console.error('[token-exchange] Subject token type:', request.subjectTokenType);
    if (request.actorToken !== undefined) {
      console.error('[token-exchange] Actor token:', request.actorToken);
      console.error('[token-exchange] Actor token type:', request.actorTokenType);
    }
    console.error('[token-exchange] Audience:', request.audience);
    console.error('[token-exchange] Scope:', request.scope);
    console.error('[token-exchange] Client ID (Basic Auth):', config.client.clientId);

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
            message: `Token exchange request failed: ${response.error.message}`,
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
      const tokenResponse = responseBody as TokenResponse & { readonly issued_token_type?: string };

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
            message: 'Invalid token exchange response: missing required fields',
          },
        };
      }

      return {
        success: true,
        tokens: toTokenExchangeResponse(tokenResponse, request),
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'network_error',
          message: 'Token exchange request failed',
          cause: error,
        },
      };
    }
  };

  return { exchange };
};
