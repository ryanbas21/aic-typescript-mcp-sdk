import { ok, err, type Result } from 'neverthrow';
import type { HttpClient } from '../http/types.js';
import type { Cache } from '../cache/types.js';
import type { AuthenticationInfo } from '../types.js';
import type { OidcDiscoveryDocument, ValidationError } from './types.js';
import { createDiscoveryError } from './errors.js';

/** Default AM realm path */
const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

/** Discovery document cache key */
const DISCOVERY_CACHE_KEY = 'oidc-discovery';

/**
 * Discovery URL variants per MCP spec priority order.
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization#authorization-server-discovery
 */
export type DiscoveryUrlVariant =
  | 'rfc8414' // RFC 8414: /.well-known/oauth-authorization-server/{path}
  | 'oidc-path' // OIDC variant: /.well-known/openid-configuration/{path}
  | 'oidc-standard'; // OIDC standard: {path}/.well-known/openid-configuration

/**
 * Result of building discovery URLs with all variants.
 */
export interface DiscoveryUrls {
  /** RFC 8414 OAuth Authorization Server Metadata URL (priority 1) */
  readonly rfc8414: string;
  /** OIDC Discovery with path suffix (priority 2) */
  readonly oidcPath: string;
  /** Standard OIDC Discovery URL (priority 3) */
  readonly oidcStandard: string;
  /** All URLs in priority order */
  readonly all: readonly string[];
}

/**
 * Builds all discovery URL variants per MCP spec.
 *
 * MCP spec requires trying these URLs in order:
 * 1. RFC 8414: https://auth.example.com/.well-known/oauth-authorization-server/tenant1
 * 2. OIDC path variant: https://auth.example.com/.well-known/openid-configuration/tenant1
 * 3. OIDC standard: https://auth.example.com/tenant1/.well-known/openid-configuration
 *
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path (default: /am/oauth2/realms/root/realms/alpha)
 * @returns Object containing all discovery URL variants
 *
 * @example
 * ```typescript
 * const urls = buildDiscoveryUrls('https://auth.example.com', '/oauth2/tenant1');
 * // urls.rfc8414 = 'https://auth.example.com/.well-known/oauth-authorization-server/oauth2/tenant1'
 * // urls.oidcPath = 'https://auth.example.com/.well-known/openid-configuration/oauth2/tenant1'
 * // urls.oidcStandard = 'https://auth.example.com/oauth2/tenant1/.well-known/openid-configuration'
 * ```
 */
export const buildDiscoveryUrls = (
  amUrl: string,
  realmPath: string = DEFAULT_REALM_PATH
): DiscoveryUrls => {
  const baseUrl = amUrl.endsWith('/') ? amUrl.slice(0, -1) : amUrl;
  const path = realmPath.startsWith('/') ? realmPath : `/${realmPath}`;

  // RFC 8414: /.well-known/oauth-authorization-server/{path}
  const rfc8414 = `${baseUrl}/.well-known/oauth-authorization-server${path}`;

  // OIDC path variant: /.well-known/openid-configuration/{path}
  const oidcPath = `${baseUrl}/.well-known/openid-configuration${path}`;

  // OIDC standard: {path}/.well-known/openid-configuration
  const oidcStandard = `${baseUrl}${path}/.well-known/openid-configuration`;

  return {
    rfc8414,
    oidcPath,
    oidcStandard,
    all: [rfc8414, oidcPath, oidcStandard],
  };
};

/**
 * Builds the OIDC discovery URL for an AM instance.
 *
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path (default: /am/oauth2/realms/root/realms/alpha)
 * @returns The well-known configuration URL (OIDC standard format)
 *
 * @deprecated Use buildDiscoveryUrls() for MCP-compliant discovery with fallback chain
 */
export const buildDiscoveryUrl = (
  amUrl: string,
  realmPath: string = DEFAULT_REALM_PATH
): string => {
  const baseUrl = amUrl.endsWith('/') ? amUrl.slice(0, -1) : amUrl;
  const path = realmPath.startsWith('/') ? realmPath : `/${realmPath}`;
  return `${baseUrl}${path}/.well-known/openid-configuration`;
};

/**
 * Validates that a discovery document has required fields.
 *
 * @param doc - The document to validate
 * @returns Result with validated document or error
 */
const validateDiscoveryDocument = (
  doc: unknown
): Result<OidcDiscoveryDocument, ValidationError> => {
  if (doc === null || typeof doc !== 'object') {
    return err(createDiscoveryError('Discovery document is not an object'));
  }

  const d = doc as Record<string, unknown>;

  if (typeof d['issuer'] !== 'string') {
    return err(createDiscoveryError('Discovery document missing "issuer"'));
  }
  if (typeof d['authorization_endpoint'] !== 'string') {
    return err(createDiscoveryError('Discovery document missing "authorization_endpoint"'));
  }
  if (typeof d['token_endpoint'] !== 'string') {
    return err(createDiscoveryError('Discovery document missing "token_endpoint"'));
  }
  if (typeof d['jwks_uri'] !== 'string') {
    return err(createDiscoveryError('Discovery document missing "jwks_uri"'));
  }
  if (!Array.isArray(d['response_types_supported'])) {
    return err(createDiscoveryError('Discovery document missing "response_types_supported"'));
  }

  return ok(d as unknown as OidcDiscoveryDocument);
};

/**
 * Result of discovery fetch with fallback information.
 */
export interface DiscoveryFetchResult {
  /** The discovered document */
  readonly document: OidcDiscoveryDocument;
  /** The URL that successfully returned the document */
  readonly successfulUrl: string;
  /** Which variant was successful */
  readonly variant: DiscoveryUrlVariant;
  /** URLs that were tried and failed before success */
  readonly triedUrls: readonly string[];
}

/**
 * Fetches the OIDC discovery document from an AM instance.
 *
 * @param httpClient - HTTP client to use for the request
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path
 * @returns Result with discovery document or error
 *
 * @deprecated Use fetchDiscoveryDocumentWithFallback() for MCP-compliant discovery
 */
export const fetchDiscoveryDocument = async (
  httpClient: HttpClient,
  amUrl: string,
  realmPath: string = DEFAULT_REALM_PATH
): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
  // eslint-disable-next-line @typescript-eslint/no-deprecated -- Internal use within deprecated function
  const url = buildDiscoveryUrl(amUrl, realmPath);

  const response = await httpClient.json<unknown>({
    url,
    method: 'GET',
  });

  if (response.isErr()) {
    return err(
      createDiscoveryError(
        `Failed to fetch discovery document: ${response.error.message}`,
        response.error
      )
    );
  }

  return validateDiscoveryDocument(response.value.body);
};

/**
 * Attempts to fetch from a single URL.
 */
const tryFetchFromUrl = async (
  httpClient: HttpClient,
  url: string
): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
  const response = await httpClient.json<unknown>({
    url,
    method: 'GET',
  });

  if (response.isErr()) {
    return err(
      createDiscoveryError(`Failed to fetch from ${url}: ${response.error.message}`, response.error)
    );
  }

  // Check for HTTP error status
  if (response.value.status >= 400) {
    return err(createDiscoveryError(`HTTP ${String(response.value.status)} from ${url}`));
  }

  return validateDiscoveryDocument(response.value.body);
};

/**
 * Fetches the discovery document with MCP-compliant fallback chain.
 *
 * Per MCP spec, tries URLs in this order:
 * 1. RFC 8414: /.well-known/oauth-authorization-server/{path}
 * 2. OIDC path variant: /.well-known/openid-configuration/{path}
 * 3. OIDC standard: {path}/.well-known/openid-configuration
 *
 * @param httpClient - HTTP client to use for requests
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path
 * @returns Result with discovery document and metadata, or error
 *
 * @example
 * ```typescript
 * const result = await fetchDiscoveryDocumentWithFallback(
 *   httpClient,
 *   'https://auth.example.com',
 *   '/oauth2/tenant1'
 * );
 *
 * if (result.isOk()) {
 *   console.log('Found at:', result.value.successfulUrl);
 *   console.log('Variant:', result.value.variant);
 *   console.log('Tried:', result.value.triedUrls);
 * }
 * ```
 */
export const fetchDiscoveryDocumentWithFallback = async (
  httpClient: HttpClient,
  amUrl: string,
  realmPath: string = DEFAULT_REALM_PATH
): Promise<Result<DiscoveryFetchResult, ValidationError>> => {
  const urls = buildDiscoveryUrls(amUrl, realmPath);
  const variants: readonly DiscoveryUrlVariant[] = ['rfc8414', 'oidc-path', 'oidc-standard'];
  const triedUrls: string[] = [];
  const errors: string[] = [];

  for (let i = 0; i < urls.all.length; i++) {
    const url = urls.all[i];
    const variant = variants[i];

    if (url === undefined || variant === undefined) {
      continue;
    }

    const result = await tryFetchFromUrl(httpClient, url);

    if (result.isOk()) {
      return ok({
        document: result.value,
        successfulUrl: url,
        variant,
        triedUrls,
      });
    }

    // Track this URL as tried
    triedUrls.push(url);
    errors.push(`${url}: ${result.error.message}`);
  }

  // All URLs failed
  return err(
    createDiscoveryError(
      `Failed to fetch discovery document from any URL. Tried:\n${errors.join('\n')}`
    )
  );
};

/**
 * Options for creating a cached discovery fetcher.
 */
export interface CachedDiscoveryFetcherOptions {
  /**
   * Whether to use MCP-compliant fallback chain (RFC 8414 -> OIDC variants).
   * When true, tries multiple discovery URLs in priority order.
   * When false, only tries the standard OIDC discovery URL.
   * @default true
   */
  readonly useFallbackChain?: boolean;
}

/**
 * Result type for cached discovery fetcher.
 */
export interface CachedDiscoveryFetcher {
  /** Fetches (or returns cached) discovery document */
  readonly fetch: () => Promise<Result<OidcDiscoveryDocument, ValidationError>>;
  /** Clears the cached discovery document */
  readonly clear: () => void;
  /** Gets the last successful discovery URL (if any) */
  readonly getLastSuccessfulUrl: () => string | undefined;
  /** Gets the last successful variant (if any) */
  readonly getLastSuccessfulVariant: () => DiscoveryUrlVariant | undefined;
}

/**
 * Creates a cached discovery document fetcher.
 *
 * By default, uses MCP-compliant fallback chain trying URLs in this order:
 * 1. RFC 8414: /.well-known/oauth-authorization-server/{path}
 * 2. OIDC path variant: /.well-known/openid-configuration/{path}
 * 3. OIDC standard: {path}/.well-known/openid-configuration
 *
 * @param httpClient - HTTP client to use for requests
 * @param cache - Cache instance for storing discovery document
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path
 * @param cacheTtlMs - Cache TTL in milliseconds
 * @param options - Additional options for discovery behavior
 * @returns CachedDiscoveryFetcher instance
 */
export const createCachedDiscoveryFetcher = (
  httpClient: HttpClient,
  cache: Cache<OidcDiscoveryDocument>,
  amUrl: string,
  realmPath = DEFAULT_REALM_PATH,
  cacheTtlMs = 3600000, // 1 hour default
  options: CachedDiscoveryFetcherOptions = {}
): CachedDiscoveryFetcher => {
  const { useFallbackChain = true } = options;

  // Track in-flight fetch to deduplicate concurrent requests
  let inFlightFetch: Promise<Result<OidcDiscoveryDocument, ValidationError>> | undefined;

  // Track last successful URL and variant for debugging/logging
  let lastSuccessfulUrl: string | undefined;
  let lastSuccessfulVariant: DiscoveryUrlVariant | undefined;

  const fetch = async (): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
    // Check cache first
    const cached = cache.get(DISCOVERY_CACHE_KEY);
    if (cached !== undefined) {
      return ok(cached);
    }

    // Return existing in-flight request if one exists
    if (inFlightFetch !== undefined) {
      return inFlightFetch;
    }

    // Create new fetch and track it
    if (useFallbackChain) {
      // MCP-compliant fallback chain
      inFlightFetch = fetchDiscoveryDocumentWithFallback(httpClient, amUrl, realmPath).then(
        (result) => {
          // Clear in-flight tracker
          inFlightFetch = undefined;

          if (result.isOk()) {
            cache.set(DISCOVERY_CACHE_KEY, result.value.document, cacheTtlMs);
            lastSuccessfulUrl = result.value.successfulUrl;
            lastSuccessfulVariant = result.value.variant;
            return ok(result.value.document);
          }

          return err(result.error);
        }
      );
    } else {
      // Legacy single-URL fetch
      // eslint-disable-next-line @typescript-eslint/no-deprecated -- Legacy mode support
      inFlightFetch = fetchDiscoveryDocument(httpClient, amUrl, realmPath).then((result) => {
        // Clear in-flight tracker
        inFlightFetch = undefined;

        if (result.isOk()) {
          cache.set(DISCOVERY_CACHE_KEY, result.value, cacheTtlMs);
          // eslint-disable-next-line @typescript-eslint/no-deprecated -- Legacy mode support
          lastSuccessfulUrl = buildDiscoveryUrl(amUrl, realmPath);
          lastSuccessfulVariant = 'oidc-standard';
        }

        return result;
      });
    }

    return inFlightFetch;
  };

  const clear = (): void => {
    cache.delete(DISCOVERY_CACHE_KEY);
  };

  const getLastSuccessfulUrl = (): string | undefined => lastSuccessfulUrl;
  const getLastSuccessfulVariant = (): DiscoveryUrlVariant | undefined => lastSuccessfulVariant;

  return { fetch, clear, getLastSuccessfulUrl, getLastSuccessfulVariant };
};

/**
 * Extracts AuthenticationInfo from a discovery document.
 *
 * @param discovery - The OIDC discovery document
 * @returns AuthenticationInfo for 401 responses
 */
export const toAuthenticationInfo = (discovery: OidcDiscoveryDocument): AuthenticationInfo => {
  const base = {
    authorizationEndpoint: discovery.authorization_endpoint,
    tokenEndpoint: discovery.token_endpoint,
    issuer: discovery.issuer,
  };

  if (discovery.scopes_supported !== undefined) {
    return { ...base, supportedScopes: discovery.scopes_supported };
  }

  return base;
};
