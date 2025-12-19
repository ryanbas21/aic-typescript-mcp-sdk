/**
 * Authorization URL builder for OAuth 2.0 authorization code flow.
 *
 * Builds authorization URLs with PKCE and state parameters per MCP spec.
 *
 * @packageDocumentation
 */

import { err, ok, type Result } from 'neverthrow';
import type { Cache } from '../cache/types.js';
import type { HttpClient } from '../http/types.js';
import type { SecureStorage } from '../storage/types.js';
import type { OidcDiscoveryDocument, ValidationError } from '../validation/types.js';
import { createCachedDiscoveryFetcher } from '../validation/discovery.js';
import { createMemoryCache } from '../cache/memory-cache.js';
import { createFetchClient } from '../http/fetch-client.js';
import { createAuthorizationState } from './state.js';
import { verifyPkceSupport } from './pkce.js';
import type {
  AuthorizationUrlOptions,
  AuthorizationUrlResult,
  TokenAcquisitionConfig,
  TokenAcquisitionError,
} from './types.js';

/** Default AM realm path */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/** Default discovery cache TTL: 1 hour */
const DEFAULT_DISCOVERY_CACHE_TTL_MS = 3600000;

/**
 * Result type for authorization URL builder operations.
 */
export type AuthorizationUrlBuilderResult = Result<AuthorizationUrlResult, TokenAcquisitionError>;

/**
 * Authorization URL builder interface.
 */
export interface AuthorizationUrlBuilder {
  /**
   * Builds an authorization URL for initiating the OAuth flow.
   *
   * @param options - Authorization options
   * @returns Result with authorization URL and state, or error
   */
  readonly build: (options?: AuthorizationUrlOptions) => Promise<AuthorizationUrlBuilderResult>;

  /**
   * Gets the cached discovery document.
   *
   * @returns Result with discovery document or error
   */
  readonly getDiscovery: () => Promise<Result<OidcDiscoveryDocument, ValidationError>>;

  /**
   * Clears the discovery cache.
   */
  readonly clearDiscoveryCache: () => void;
}

/**
 * Converts a TokenAcquisitionError to have a discovery_error code.
 */
const toDiscoveryError = (error: ValidationError): TokenAcquisitionError => ({
  code: 'discovery_error',
  message: error.message,
  cause: error.cause,
});

/**
 * Builds the authorization URL with all required parameters.
 */
const buildUrl = (
  authorizationEndpoint: string,
  params: {
    readonly clientId: string;
    readonly redirectUri: string;
    readonly scope: string;
    readonly state: string;
    readonly codeChallenge: string;
    readonly codeChallengeMethod: string;
    readonly nonce?: string | undefined;
    readonly resource?: string | undefined;
    readonly prompt?: string | undefined;
    readonly loginHint?: string | undefined;
    readonly acrValues?: string | undefined;
  }
): string => {
  const url = new URL(authorizationEndpoint);

  // Required parameters
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.scope);
  url.searchParams.set('state', params.state);

  // PKCE parameters (required per MCP spec)
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', params.codeChallengeMethod);

  // Optional parameters
  if (params.nonce !== undefined) {
    url.searchParams.set('nonce', params.nonce);
  }

  // RFC 8707 resource parameter (required per MCP spec)
  if (params.resource !== undefined) {
    url.searchParams.set('resource', params.resource);
  }

  if (params.prompt !== undefined) {
    url.searchParams.set('prompt', params.prompt);
  }

  if (params.loginHint !== undefined) {
    url.searchParams.set('login_hint', params.loginHint);
  }

  if (params.acrValues !== undefined) {
    url.searchParams.set('acr_values', params.acrValues);
  }

  return url.toString();
};

/**
 * Creates an authorization URL builder.
 *
 * @param config - Token acquisition configuration
 * @param storage - Secure storage for PKCE and state
 * @param httpClient - HTTP client for discovery (optional)
 * @param discoveryCache - Cache for discovery document (optional)
 * @returns AuthorizationUrlBuilder instance
 *
 * @example
 * ```typescript
 * const builder = createAuthorizationUrlBuilder(
 *   {
 *     amUrl: 'https://auth.example.com',
 *     client: {
 *       clientType: 'public',
 *       clientId: 'my-app',
 *       redirectUri: 'https://app.example.com/callback',
 *       scopes: ['openid', 'profile'],
 *     },
 *   },
 *   storage
 * );
 *
 * const result = await builder.build({
 *   scopes: ['openid', 'profile', 'email'],
 *   resource: 'https://api.example.com',
 * });
 *
 * if (result.isOk()) {
 *   // Redirect user to result.value.url
 *   // Store result.value.state for callback validation
 * }
 * ```
 */
export const createAuthorizationUrlBuilder = (
  config: TokenAcquisitionConfig,
  storage: SecureStorage,
  httpClient: HttpClient = createFetchClient(),
  discoveryCache: Cache<OidcDiscoveryDocument> = createMemoryCache(
    config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS
  )
): AuthorizationUrlBuilder => {
  const realmPath = config.realmPath ?? DEFAULT_REALM_PATH;
  const cacheTtlMs = config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS;

  // Create cached discovery fetcher (reusing existing infrastructure)
  const discoveryFetcher = createCachedDiscoveryFetcher(
    httpClient,
    discoveryCache,
    config.amUrl,
    realmPath,
    cacheTtlMs
  );

  const build = async (
    options?: AuthorizationUrlOptions
  ): Promise<AuthorizationUrlBuilderResult> => {
    // Fetch discovery document
    const discoveryResult = await discoveryFetcher.fetch();
    if (discoveryResult.isErr()) {
      return err(toDiscoveryError(discoveryResult.error));
    }

    const discovery = discoveryResult.value;

    // Verify PKCE support per MCP spec
    // MCP spec requires clients to verify code_challenge_methods_supported includes S256
    const pkceSupportResult = verifyPkceSupport(discovery);

    // If PKCE is definitively NOT supported (field exists but no S256), fail
    if (!pkceSupportResult.supported && pkceSupportResult.warning === undefined) {
      return err({
        code: 'pkce_error',
        message:
          `Authorization server does not support PKCE S256. ` +
          `Supported methods: ${pkceSupportResult.supportedMethods.length > 0 ? pkceSupportResult.supportedMethods.join(', ') : 'none'}. ` +
          `MCP spec requires PKCE S256 support.`,
      });
    }

    // Create authorization state (includes PKCE generation)
    const stateResult = await createAuthorizationState(storage, options, {
      redirectUri: config.client.redirectUri,
      scopes: config.client.scopes,
    });

    if (stateResult.isErr()) {
      return err(stateResult.error);
    }

    const authState = stateResult.value;

    // Build the authorization URL
    const url = buildUrl(discovery.authorization_endpoint, {
      clientId: config.client.clientId,
      redirectUri: authState.redirectUri,
      scope: authState.scopes.join(' '),
      state: authState.state,
      codeChallenge: authState.pkce.challenge,
      codeChallengeMethod: authState.pkce.method,
      nonce: authState.nonce,
      resource: authState.resource ?? options?.resource,
      prompt: options?.prompt,
      loginHint: options?.loginHint,
      acrValues: options?.acrValues,
    });

    return ok({
      url,
      state: authState.state,
      authorizationState: authState,
      pkceSupport: {
        verified: pkceSupportResult.supported,
        supportedMethods: pkceSupportResult.supportedMethods,
        warning: pkceSupportResult.warning,
      },
    });
  };

  const getDiscovery = (): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
    return discoveryFetcher.fetch();
  };

  const clearDiscoveryCache = (): void => {
    discoveryFetcher.clear();
  };

  return {
    build,
    getDiscovery,
    clearDiscoveryCache,
  };
};
