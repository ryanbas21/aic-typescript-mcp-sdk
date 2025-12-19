/**
 * Token manager orchestrating all OAuth token acquisition flows.
 *
 * Provides a unified interface for:
 * - Authorization code flow (user authentication)
 * - Token refresh (on-demand)
 * - Client credentials (service tokens)
 * - Token exchange (identity delegation)
 *
 * @packageDocumentation
 */

import type { Cache } from '../cache/types.js';
import { createMemoryCache } from '../cache/memory-cache.js';
import type { HttpClient } from '../http/types.js';
import { createFetchClient } from '../http/fetch-client.js';
import type { SecureStorage } from '../storage/types.js';
import { createMemoryStorage } from '../storage/memory-storage.js';
import type { OidcDiscoveryDocument } from '../validation/types.js';
import {
  createAuthorizationUrlBuilder,
  type AuthorizationUrlBuilder,
} from './authorization-url.js';
import { createTokenClient, type TokenClient } from './token-client.js';
import {
  createClientCredentialsAcquirer,
  type ClientCredentialsAcquirer,
} from './client-credentials.js';
import { createTokenExchanger, type TokenExchanger } from './token-exchange.js';
import { consumeAuthorizationState } from './state.js';
import type {
  AuthorizationUrlOptions,
  AuthorizationUrlResult,
  ClientCredentialsOptions,
  ConfidentialClientConfig,
  TokenAcquisitionError,
  TokenAcquisitionResult,
  TokenExchangeRequest,
  TokenExchangeResult,
  TokenManager,
  TokenManagerConfig,
  TokenSet,
} from './types.js';
import { isConfidentialClient } from './types.js';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 3600000;

/** Default refresh buffer: 60 seconds before expiry */
const DEFAULT_REFRESH_BUFFER_SECONDS = 60;

/** Storage key for current token set */
const TOKEN_SET_KEY = 'oauth:tokens:current';

/**
 * Type guard for confidential client config.
 */
const isConfidentialClientConfig = (
  config: TokenManagerConfig
): config is TokenManagerConfig & { readonly client: ConfidentialClientConfig } => {
  return isConfidentialClient(config.client);
};

/**
 * Creates a token manager for orchestrating OAuth flows.
 *
 * The token manager provides a unified interface for all token acquisition
 * operations, with on-demand refresh of expired tokens.
 *
 * @param config - Token manager configuration
 * @param storage - Secure storage for tokens and state (optional, defaults to in-memory)
 * @param httpClient - HTTP client (optional)
 * @param discoveryCache - Cache for discovery document (optional)
 * @returns TokenManager instance
 *
 * @example
 * ```typescript
 * // Create token manager
 * const tokenManager = createTokenManager({
 *   amUrl: 'https://auth.example.com',
 *   client: {
 *     clientType: 'confidential',
 *     clientId: 'my-mcp-server',
 *     clientSecret: 'secret',
 *     redirectUri: 'https://mcp.example.com/callback',
 *     scopes: ['openid', 'profile'],
 *   },
 * });
 *
 * // Start authorization flow
 * const { url, state } = await tokenManager.startAuthorization();
 * // Redirect user to `url`
 *
 * // After callback, handle the code
 * const result = await tokenManager.handleCallback(code, state);
 *
 * // Later, get access token (auto-refreshes if needed)
 * const tokenResult = await tokenManager.getAccessToken();
 * if (tokenResult.success) {
 *   // Use tokenResult.accessToken
 * }
 *
 * // Exchange user token for downstream API call
 * const exchangeResult = await tokenManager.exchangeToken({
 *   subjectToken: userToken,
 *   subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
 *   audience: 'downstream-api',
 * });
 * ```
 */
export const createTokenManager = (
  config: TokenManagerConfig,
  storage: SecureStorage = createMemoryStorage(),
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(
    config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  )
): TokenManager => {
  const refreshBufferSeconds = config.refreshBufferSeconds ?? DEFAULT_REFRESH_BUFFER_SECONDS;

  // Create internal components
  const authUrlBuilder: AuthorizationUrlBuilder = createAuthorizationUrlBuilder(
    config,
    storage,
    httpClient,
    discoveryCache
  );

  const tokenClient: TokenClient = createTokenClient(config, httpClient, discoveryCache);

  // Create confidential-client-only components lazily
  let clientCredentialsAcquirer: ClientCredentialsAcquirer | undefined;
  let tokenExchanger: TokenExchanger | undefined;

  if (isConfidentialClientConfig(config)) {
    clientCredentialsAcquirer = createClientCredentialsAcquirer(
      { ...config, client: config.client },
      httpClient,
      discoveryCache
    );

    tokenExchanger = createTokenExchanger(
      { ...config, client: config.client },
      httpClient,
      discoveryCache
    );
  }

  /**
   * Stores the current token set.
   */
  const storeTokenSet = async (tokens: TokenSet): Promise<void> => {
    await storage.set(TOKEN_SET_KEY, JSON.stringify(tokens));
  };

  /**
   * Retrieves the current token set.
   */
  const retrieveTokenSet = async (): Promise<TokenSet | undefined> => {
    const stored = await storage.get(TOKEN_SET_KEY);
    if (stored === undefined) {
      return undefined;
    }

    try {
      return JSON.parse(stored) as TokenSet;
    } catch {
      return undefined;
    }
  };

  /**
   * Checks if a token is expiring within the buffer period.
   */
  const isTokenExpiring = (tokens: TokenSet): boolean => {
    const now = Date.now();
    const bufferMs = refreshBufferSeconds * 1000;
    return tokens.expiresAt - bufferMs <= now;
  };

  /**
   * Starts the authorization code flow.
   */
  const startAuthorization = async (
    options?: AuthorizationUrlOptions
  ): Promise<TokenAcquisitionResult | AuthorizationUrlResult> => {
    const result = await authUrlBuilder.build(options);

    if (result.isErr()) {
      return {
        success: false,
        error: result.error,
      };
    }

    return result.value;
  };

  /**
   * Handles the OAuth callback and exchanges code for tokens.
   */
  const handleCallback = async (code: string, state: string): Promise<TokenAcquisitionResult> => {
    // Retrieve and consume authorization state
    const stateResult = await consumeAuthorizationState(storage, state);

    if (stateResult.isErr()) {
      return {
        success: false,
        error: stateResult.error,
      };
    }

    const authState = stateResult.value;

    // Exchange code for tokens
    const result = await tokenClient.exchangeCode({
      code,
      codeVerifier: authState.pkce.verifier,
      redirectUri: authState.redirectUri,
      resource: authState.resource,
    });

    if (result.success) {
      // Store the tokens
      await storeTokenSet(result.tokens);
    }

    return result;
  };

  /**
   * Gets a valid access token, refreshing if necessary.
   */
  const getAccessToken = async (): Promise<
    | { readonly success: true; readonly accessToken: string }
    | { readonly success: false; readonly error: TokenAcquisitionError }
  > => {
    const tokens = await retrieveTokenSet();

    if (tokens === undefined) {
      return {
        success: false,
        error: {
          code: 'invalid_grant',
          message: 'No tokens available. User must authenticate first.',
        },
      };
    }

    // Check if token needs refresh
    if (isTokenExpiring(tokens)) {
      if (tokens.refreshToken === undefined) {
        return {
          success: false,
          error: {
            code: 'expired_token',
            message: 'Access token expired and no refresh token available.',
          },
        };
      }

      // Attempt refresh
      const refreshResult = await tokenClient.refresh({
        refreshToken: tokens.refreshToken,
      });

      if (!refreshResult.success) {
        return {
          success: false,
          error: refreshResult.error,
        };
      }

      // Store refreshed tokens
      await storeTokenSet(refreshResult.tokens);

      return {
        success: true,
        accessToken: refreshResult.tokens.accessToken,
      };
    }

    return {
      success: true,
      accessToken: tokens.accessToken,
    };
  };

  /**
   * Gets the current token set.
   */
  const getTokenSet = async (): Promise<TokenSet | undefined> => {
    return retrieveTokenSet();
  };

  /**
   * Gets a service token using client credentials.
   */
  const getServiceToken = async (
    options?: ClientCredentialsOptions
  ): Promise<TokenAcquisitionResult> => {
    if (clientCredentialsAcquirer === undefined) {
      return {
        success: false,
        error: {
          code: 'unauthorized_client',
          message: 'Client credentials flow requires a confidential client.',
        },
      };
    }

    return clientCredentialsAcquirer.acquire(options);
  };

  /**
   * Exchanges a token for a new token (RFC 8693).
   */
  const exchangeToken = async (request: TokenExchangeRequest): Promise<TokenExchangeResult> => {
    if (tokenExchanger === undefined) {
      return {
        success: false,
        error: {
          code: 'unauthorized_client',
          message: 'Token exchange requires a confidential client.',
        },
      };
    }

    return tokenExchanger.exchange(request);
  };

  /**
   * Clears all stored tokens.
   */
  const clearTokens = async (): Promise<void> => {
    await storage.delete(TOKEN_SET_KEY);
  };

  /**
   * Revokes the current access token.
   */
  const revokeToken = async (): Promise<
    | { readonly success: true; readonly revoked: true }
    | { readonly success: false; readonly error: TokenAcquisitionError }
  > => {
    const tokens = await retrieveTokenSet();

    if (tokens === undefined) {
      return {
        success: false,
        error: {
          code: 'invalid_token',
          message: 'No token to revoke.',
        },
      };
    }

    // Get discovery to find revocation endpoint
    const discoveryResult = await tokenClient.getDiscovery();
    if (discoveryResult.isErr()) {
      return {
        success: false,
        error: {
          code: 'discovery_error',
          message: discoveryResult.error.message,
          cause: discoveryResult.error.cause,
        },
      };
    }

    const discovery = discoveryResult.value;

    if (discovery.revocation_endpoint === undefined) {
      return {
        success: false,
        error: {
          code: 'unsupported_grant_type',
          message: 'Authorization server does not support token revocation.',
        },
      };
    }

    // Build revocation request
    const body: Record<string, string> = {
      token: tokens.accessToken,
      token_type_hint: 'access_token',
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    // Add client authentication for confidential clients
    if (isConfidentialClientConfig(config)) {
      const credentials = `${config.client.clientId}:${config.client.clientSecret}`;
      headers['Authorization'] = `Basic ${btoa(credentials)}`;
    } else {
      body['client_id'] = config.client.clientId;
    }

    const bodyString = new URLSearchParams(body).toString();

    try {
      const response = await httpClient.json<unknown>({
        url: discovery.revocation_endpoint,
        method: 'POST',
        headers,
        body: bodyString,
      });

      if (response.isErr()) {
        return {
          success: false,
          error: {
            code: 'network_error',
            message: `Revocation request failed: ${response.error.message}`,
            cause: response.error,
          },
        };
      }

      // Clear stored tokens after successful revocation
      await clearTokens();

      return {
        success: true,
        revoked: true,
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'network_error',
          message: 'Revocation request failed',
          cause: error,
        },
      };
    }
  };

  return {
    startAuthorization,
    handleCallback,
    getAccessToken,
    getTokenSet,
    getServiceToken,
    exchangeToken,
    clearTokens,
    revokeToken,
  };
};
