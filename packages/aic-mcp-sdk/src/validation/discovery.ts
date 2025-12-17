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
 * Builds the OIDC discovery URL for an AM instance.
 *
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path (default: /am/oauth2/realms/root/realms/alpha)
 * @returns The well-known configuration URL
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
 * Fetches the OIDC discovery document from an AM instance.
 *
 * @param httpClient - HTTP client to use for the request
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path
 * @returns Result with discovery document or error
 */
export const fetchDiscoveryDocument = async (
  httpClient: HttpClient,
  amUrl: string,
  realmPath: string = DEFAULT_REALM_PATH
): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
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
 * Creates a cached discovery document fetcher.
 *
 * @param httpClient - HTTP client to use for requests
 * @param cache - Cache instance for storing discovery document
 * @param amUrl - Base URL of the AM instance
 * @param realmPath - OAuth realm path
 * @param cacheTtlMs - Cache TTL in milliseconds
 * @returns Function that fetches (or returns cached) discovery document
 */
export const createCachedDiscoveryFetcher = (
  httpClient: HttpClient,
  cache: Cache<OidcDiscoveryDocument>,
  amUrl: string,
  realmPath = DEFAULT_REALM_PATH,
  cacheTtlMs = 3600000 // 1 hour default
): {
  readonly fetch: () => Promise<Result<OidcDiscoveryDocument, ValidationError>>;
  readonly clear: () => void;
} => {
  const fetch = async (): Promise<Result<OidcDiscoveryDocument, ValidationError>> => {
    // Check cache first
    const cached = cache.get(DISCOVERY_CACHE_KEY);
    if (cached !== undefined) {
      return ok(cached);
    }

    // Fetch fresh document
    const result = await fetchDiscoveryDocument(httpClient, amUrl, realmPath);

    if (result.isOk()) {
      cache.set(DISCOVERY_CACHE_KEY, result.value, cacheTtlMs);
    }

    return result;
  };

  const clear = (): void => {
    cache.delete(DISCOVERY_CACHE_KEY);
  };

  return { fetch, clear };
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
