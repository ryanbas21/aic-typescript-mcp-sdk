import { describe, it, expect } from 'vitest';
import {
  buildDiscoveryUrl,
  fetchDiscoveryDocument,
  createCachedDiscoveryFetcher,
  toAuthenticationInfo,
} from './discovery.js';
import { createSuccessHttpClient, createErrorHttpClient, createMockCache } from '../test/mocks.js';
import {
  TEST_AM_URL,
  TEST_REALM_PATH,
  TEST_ISSUER,
  TEST_JWKS_URI,
  TEST_AUTHORIZATION_ENDPOINT,
  TEST_TOKEN_ENDPOINT,
  createDiscoveryDocument,
  ONE_HOUR_MS,
} from '../test/fixtures.js';

// ============================================================================
// buildDiscoveryUrl Tests
// ============================================================================

describe('buildDiscoveryUrl', () => {
  const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

  describe('given base URL without trailing slash', () => {
    it('constructs correct discovery URL', () => {
      const result = buildDiscoveryUrl(TEST_AM_URL, TEST_REALM_PATH);

      expect(result).toBe(`${TEST_AM_URL}${TEST_REALM_PATH}/.well-known/openid-configuration`);
    });
  });

  describe('given base URL with trailing slash', () => {
    it('removes trailing slash before constructing URL', () => {
      const urlWithSlash = `${TEST_AM_URL}/`;

      const result = buildDiscoveryUrl(urlWithSlash, TEST_REALM_PATH);

      expect(result).toBe(`${TEST_AM_URL}${TEST_REALM_PATH}/.well-known/openid-configuration`);
    });
  });

  describe('given realm path without leading slash', () => {
    it('adds leading slash to realm path', () => {
      const realmWithoutSlash = 'am/oauth2/realms/custom';

      const result = buildDiscoveryUrl(TEST_AM_URL, realmWithoutSlash);

      expect(result).toBe(`${TEST_AM_URL}/${realmWithoutSlash}/.well-known/openid-configuration`);
    });
  });

  describe('given no realm path', () => {
    it('uses default realm path', () => {
      const result = buildDiscoveryUrl(TEST_AM_URL);

      expect(result).toBe(`${TEST_AM_URL}${DEFAULT_REALM_PATH}/.well-known/openid-configuration`);
    });
  });
});

// ============================================================================
// fetchDiscoveryDocument Tests
// ============================================================================

describe('fetchDiscoveryDocument', () => {
  describe('given successful HTTP response with valid document', () => {
    it('returns Ok with parsed discovery document', async () => {
      const discoveryDoc = createDiscoveryDocument();
      const httpClient = createSuccessHttpClient(discoveryDoc);

      const result = await fetchDiscoveryDocument(httpClient, TEST_AM_URL, TEST_REALM_PATH);

      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.issuer).toBe(TEST_ISSUER);
        expect(result.value.jwks_uri).toBe(TEST_JWKS_URI);
        expect(result.value.authorization_endpoint).toBe(TEST_AUTHORIZATION_ENDPOINT);
        expect(result.value.token_endpoint).toBe(TEST_TOKEN_ENDPOINT);
      }
    });
  });

  describe('given HTTP error', () => {
    it('returns Err with DISCOVERY_ERROR', async () => {
      const httpClient = createErrorHttpClient('Network error', 500);

      const result = await fetchDiscoveryDocument(httpClient, TEST_AM_URL, TEST_REALM_PATH);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('DISCOVERY_ERROR');
        expect(result.error.message).toContain('Failed to fetch discovery document');
      }
    });
  });

  describe('given response is not an object', () => {
    it('returns Err with DISCOVERY_ERROR', async () => {
      const httpClient = createSuccessHttpClient('not an object');

      const result = await fetchDiscoveryDocument(httpClient, TEST_AM_URL, TEST_REALM_PATH);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('DISCOVERY_ERROR');
        expect(result.error.message).toContain('not an object');
      }
    });
  });

  describe('given response missing issuer', () => {
    it('returns Err with DISCOVERY_ERROR', async () => {
      const invalidDoc = {
        authorization_endpoint: TEST_AUTHORIZATION_ENDPOINT,
        token_endpoint: TEST_TOKEN_ENDPOINT,
        jwks_uri: TEST_JWKS_URI,
        response_types_supported: ['code'],
      };
      const httpClient = createSuccessHttpClient(invalidDoc);

      const result = await fetchDiscoveryDocument(httpClient, TEST_AM_URL, TEST_REALM_PATH);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('issuer');
      }
    });
  });

  describe('given response missing jwks_uri', () => {
    it('returns Err with DISCOVERY_ERROR', async () => {
      const invalidDoc = {
        issuer: TEST_ISSUER,
        authorization_endpoint: TEST_AUTHORIZATION_ENDPOINT,
        token_endpoint: TEST_TOKEN_ENDPOINT,
        response_types_supported: ['code'],
      };
      const httpClient = createSuccessHttpClient(invalidDoc);

      const result = await fetchDiscoveryDocument(httpClient, TEST_AM_URL, TEST_REALM_PATH);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('jwks_uri');
      }
    });
  });

  describe('given response missing response_types_supported', () => {
    it('returns Err with DISCOVERY_ERROR', async () => {
      const invalidDoc = {
        issuer: TEST_ISSUER,
        authorization_endpoint: TEST_AUTHORIZATION_ENDPOINT,
        token_endpoint: TEST_TOKEN_ENDPOINT,
        jwks_uri: TEST_JWKS_URI,
      };
      const httpClient = createSuccessHttpClient(invalidDoc);

      const result = await fetchDiscoveryDocument(httpClient, TEST_AM_URL, TEST_REALM_PATH);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('response_types_supported');
      }
    });
  });
});

// ============================================================================
// createCachedDiscoveryFetcher Tests
// ============================================================================

describe('createCachedDiscoveryFetcher', () => {
  describe('fetch', () => {
    describe('given cache miss', () => {
      it('fetches from HTTP and caches result', async () => {
        const discoveryDoc = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discoveryDoc);
        const cache = createMockCache();

        const fetcher = createCachedDiscoveryFetcher(
          httpClient,
          cache,
          TEST_AM_URL,
          TEST_REALM_PATH,
          ONE_HOUR_MS
        );

        const result = await fetcher.fetch();

        expect(result.isOk()).toBe(true);
        expect(cache.setCalls.length).toBe(1);
        expect(cache.setCalls[0]?.key).toBe('oidc-discovery');
        expect(cache.setCalls[0]?.ttlMs).toBe(ONE_HOUR_MS);
      });
    });

    describe('given cache hit', () => {
      it('returns cached value without HTTP request', async () => {
        const cachedDoc = createDiscoveryDocument();
        const httpClient = createErrorHttpClient('Should not be called');
        const cache = createMockCache({ 'oidc-discovery': cachedDoc });

        const fetcher = createCachedDiscoveryFetcher(
          httpClient,
          cache,
          TEST_AM_URL,
          TEST_REALM_PATH,
          ONE_HOUR_MS
        );

        const result = await fetcher.fetch();

        expect(result.isOk()).toBe(true);
        if (result.isOk()) {
          expect(result.value).toEqual(cachedDoc);
        }
      });
    });

    describe('given HTTP error', () => {
      it('does not cache error result', async () => {
        const httpClient = createErrorHttpClient('Network error');
        const cache = createMockCache();

        const fetcher = createCachedDiscoveryFetcher(
          httpClient,
          cache,
          TEST_AM_URL,
          TEST_REALM_PATH,
          ONE_HOUR_MS
        );

        const result = await fetcher.fetch();

        expect(result.isErr()).toBe(true);
        expect(cache.setCalls.length).toBe(0);
      });
    });
  });

  describe('clear', () => {
    it('removes cached discovery document', async () => {
      const discoveryDoc = createDiscoveryDocument();
      const httpClient = createSuccessHttpClient(discoveryDoc);
      const cache = createMockCache();

      const fetcher = createCachedDiscoveryFetcher(
        httpClient,
        cache,
        TEST_AM_URL,
        TEST_REALM_PATH,
        ONE_HOUR_MS
      );

      await fetcher.fetch();
      fetcher.clear();

      expect(cache.deleteCalls).toContain('oidc-discovery');
    });
  });
});

// ============================================================================
// toAuthenticationInfo Tests
// ============================================================================

describe('toAuthenticationInfo', () => {
  describe('given discovery document with all fields', () => {
    it('extracts authentication info', () => {
      const discovery = createDiscoveryDocument();

      const result = toAuthenticationInfo(discovery);

      expect(result.authorizationEndpoint).toBe(TEST_AUTHORIZATION_ENDPOINT);
      expect(result.tokenEndpoint).toBe(TEST_TOKEN_ENDPOINT);
      expect(result.issuer).toBe(TEST_ISSUER);
    });
  });

  describe('given discovery document with scopes_supported', () => {
    it('includes supported scopes', () => {
      const scopes = ['openid', 'profile', 'email'];
      const discovery = createDiscoveryDocument({ scopes_supported: scopes });

      const result = toAuthenticationInfo(discovery);

      expect(result.supportedScopes).toEqual(scopes);
    });
  });

  describe('given discovery document without scopes_supported', () => {
    it('omits supportedScopes field', () => {
      const discovery = createDiscoveryDocument();
      // Remove scopes_supported by creating a new object without it
      const { scopes_supported: _, ...discoveryWithoutScopes } = discovery;
      const docWithoutScopes = discoveryWithoutScopes as typeof discovery;

      const result = toAuthenticationInfo(docWithoutScopes);

      expect(result.supportedScopes).toBeUndefined();
    });
  });
});
