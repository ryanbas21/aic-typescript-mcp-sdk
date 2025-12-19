import { describe, it, expect } from 'vitest';
import {
  buildDiscoveryUrl,
  buildDiscoveryUrls,
  fetchDiscoveryDocument,
  fetchDiscoveryDocumentWithFallback,
  createCachedDiscoveryFetcher,
  toAuthenticationInfo,
} from './discovery.js';
import type { HttpClient } from '../http/types.js';
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
// buildDiscoveryUrl Tests (deprecated, kept for backwards compatibility)
// ============================================================================

/* eslint-disable @typescript-eslint/no-deprecated -- Testing deprecated function for backwards compatibility */
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
/* eslint-enable @typescript-eslint/no-deprecated */

// ============================================================================
// buildDiscoveryUrls Tests (RFC 8414 MCP-compliant)
// ============================================================================

describe('buildDiscoveryUrls', () => {
  const DEFAULT_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';

  describe('given base URL and realm path', () => {
    it('buildDiscoveryUrls_ValidInputs_ReturnsAllThreeVariants', () => {
      // Arrange
      const amUrl = 'https://auth.example.com';
      const realmPath = '/oauth2/tenant1';

      // Act
      const result = buildDiscoveryUrls(amUrl, realmPath);

      // Assert
      expect(result.rfc8414).toBe(
        'https://auth.example.com/.well-known/oauth-authorization-server/oauth2/tenant1'
      );
      expect(result.oidcPath).toBe(
        'https://auth.example.com/.well-known/openid-configuration/oauth2/tenant1'
      );
      expect(result.oidcStandard).toBe(
        'https://auth.example.com/oauth2/tenant1/.well-known/openid-configuration'
      );
    });

    it('buildDiscoveryUrls_ValidInputs_ReturnsAllUrlsInPriorityOrder', () => {
      // Arrange
      const amUrl = 'https://auth.example.com';
      const realmPath = '/oauth2/tenant1';

      // Act
      const result = buildDiscoveryUrls(amUrl, realmPath);

      // Assert
      expect(result.all).toHaveLength(3);
      expect(result.all[0]).toBe(result.rfc8414);
      expect(result.all[1]).toBe(result.oidcPath);
      expect(result.all[2]).toBe(result.oidcStandard);
    });
  });

  describe('given URL with trailing slash', () => {
    it('buildDiscoveryUrls_TrailingSlash_RemovesTrailingSlash', () => {
      // Arrange
      const amUrl = 'https://auth.example.com/';
      const realmPath = '/oauth2/tenant1';

      // Act
      const result = buildDiscoveryUrls(amUrl, realmPath);

      // Assert
      expect(result.rfc8414).toBe(
        'https://auth.example.com/.well-known/oauth-authorization-server/oauth2/tenant1'
      );
    });
  });

  describe('given realm path without leading slash', () => {
    it('buildDiscoveryUrls_NoLeadingSlash_AddsLeadingSlash', () => {
      // Arrange
      const amUrl = 'https://auth.example.com';
      const realmPath = 'oauth2/tenant1';

      // Act
      const result = buildDiscoveryUrls(amUrl, realmPath);

      // Assert
      expect(result.rfc8414).toBe(
        'https://auth.example.com/.well-known/oauth-authorization-server/oauth2/tenant1'
      );
    });
  });

  describe('given no realm path', () => {
    it('buildDiscoveryUrls_NoRealmPath_UsesDefaultRealmPath', () => {
      // Arrange
      const amUrl = 'https://auth.example.com';

      // Act
      const result = buildDiscoveryUrls(amUrl);

      // Assert
      expect(result.rfc8414).toBe(
        `https://auth.example.com/.well-known/oauth-authorization-server${DEFAULT_REALM_PATH}`
      );
      expect(result.oidcStandard).toBe(
        `https://auth.example.com${DEFAULT_REALM_PATH}/.well-known/openid-configuration`
      );
    });
  });

  describe('given AM-style realm path', () => {
    it('buildDiscoveryUrls_AmRealmPath_ConstructsCorrectUrls', () => {
      // Arrange
      const amUrl = TEST_AM_URL;
      const realmPath = TEST_REALM_PATH;

      // Act
      const result = buildDiscoveryUrls(amUrl, realmPath);

      // Assert
      expect(result.rfc8414).toBe(
        `${TEST_AM_URL}/.well-known/oauth-authorization-server${TEST_REALM_PATH}`
      );
      expect(result.oidcPath).toBe(
        `${TEST_AM_URL}/.well-known/openid-configuration${TEST_REALM_PATH}`
      );
      expect(result.oidcStandard).toBe(
        `${TEST_AM_URL}${TEST_REALM_PATH}/.well-known/openid-configuration`
      );
    });
  });
});

// ============================================================================
// fetchDiscoveryDocumentWithFallback Tests (RFC 8414 MCP-compliant)
// ============================================================================

describe('fetchDiscoveryDocumentWithFallback', () => {
  /**
   * Creates a mock HTTP client that succeeds only for specific URLs.
   */
  const createSelectiveHttpClient = (
    successUrls: readonly string[],
    discoveryDoc: Record<string, unknown>
  ): HttpClient => ({
    json: (request: { readonly url: string }) => {
      if (successUrls.includes(request.url)) {
        return Promise.resolve({
          isOk: () => true as const,
          isErr: () => false as const,
          value: { body: discoveryDoc, status: 200, headers: {} },
          error: undefined as never,
        });
      }
      return Promise.resolve({
        isOk: () => false as const,
        isErr: () => true as const,
        value: undefined as never,
        error: { message: `HTTP 404 from ${request.url}`, code: 'FETCH_ERROR' },
      });
    },
    form: () => Promise.reject(new Error('Not implemented')),
  });

  /**
   * Creates a mock HTTP client that returns specific status codes per URL.
   */
  const createStatusHttpClient = (
    urlStatuses: Record<string, number>,
    discoveryDoc: Record<string, unknown>
  ): HttpClient => ({
    json: (request: { readonly url: string }) => {
      const status = urlStatuses[request.url] ?? 404;
      if (status >= 200 && status < 400) {
        return Promise.resolve({
          isOk: () => true as const,
          isErr: () => false as const,
          value: { body: discoveryDoc, status, headers: {} },
          error: undefined as never,
        });
      }
      // Return success response but with error status (for HTTP 4xx/5xx testing)
      return Promise.resolve({
        isOk: () => true as const,
        isErr: () => false as const,
        value: { body: {}, status, headers: {} },
        error: undefined as never,
      });
    },
    form: () => Promise.reject(new Error('Not implemented')),
  });

  const validDiscoveryDoc = {
    issuer: TEST_ISSUER,
    authorization_endpoint: TEST_AUTHORIZATION_ENDPOINT,
    token_endpoint: TEST_TOKEN_ENDPOINT,
    jwks_uri: TEST_JWKS_URI,
    response_types_supported: ['code'],
  };

  describe('given first URL (RFC 8414) succeeds', () => {
    it('fetchDiscoveryDocumentWithFallback_Rfc8414Succeeds_ReturnsWithRfc8414Variant', async () => {
      // Arrange
      const urls = buildDiscoveryUrls(TEST_AM_URL, TEST_REALM_PATH);
      const httpClient = createSelectiveHttpClient([urls.rfc8414], validDiscoveryDoc);

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.variant).toBe('rfc8414');
        expect(result.value.successfulUrl).toBe(urls.rfc8414);
        expect(result.value.triedUrls).toHaveLength(0);
        expect(result.value.document.issuer).toBe(TEST_ISSUER);
      }
    });
  });

  describe('given second URL (OIDC path) succeeds after first fails', () => {
    it('fetchDiscoveryDocumentWithFallback_OidcPathSucceeds_ReturnsWithOidcPathVariant', async () => {
      // Arrange
      const urls = buildDiscoveryUrls(TEST_AM_URL, TEST_REALM_PATH);
      const httpClient = createSelectiveHttpClient([urls.oidcPath], validDiscoveryDoc);

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.variant).toBe('oidc-path');
        expect(result.value.successfulUrl).toBe(urls.oidcPath);
        expect(result.value.triedUrls).toHaveLength(1);
        expect(result.value.triedUrls[0]).toBe(urls.rfc8414);
      }
    });
  });

  describe('given third URL (OIDC standard) succeeds after first two fail', () => {
    it('fetchDiscoveryDocumentWithFallback_OidcStandardSucceeds_ReturnsWithOidcStandardVariant', async () => {
      // Arrange
      const urls = buildDiscoveryUrls(TEST_AM_URL, TEST_REALM_PATH);
      const httpClient = createSelectiveHttpClient([urls.oidcStandard], validDiscoveryDoc);

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.variant).toBe('oidc-standard');
        expect(result.value.successfulUrl).toBe(urls.oidcStandard);
        expect(result.value.triedUrls).toHaveLength(2);
        expect(result.value.triedUrls[0]).toBe(urls.rfc8414);
        expect(result.value.triedUrls[1]).toBe(urls.oidcPath);
      }
    });
  });

  describe('given all URLs fail', () => {
    it('fetchDiscoveryDocumentWithFallback_AllFail_ReturnsErrorWithAllUrls', async () => {
      // Arrange
      const httpClient = createSelectiveHttpClient([], validDiscoveryDoc);

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('DISCOVERY_ERROR');
        expect(result.error.message).toContain('Failed to fetch discovery document from any URL');
      }
    });
  });

  describe('given HTTP 404 status from first URL', () => {
    it('fetchDiscoveryDocumentWithFallback_Http404_TriesNextUrl', async () => {
      // Arrange
      const urls = buildDiscoveryUrls(TEST_AM_URL, TEST_REALM_PATH);
      const httpClient = createStatusHttpClient(
        {
          [urls.rfc8414]: 404,
          [urls.oidcPath]: 200,
        },
        validDiscoveryDoc
      );

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.variant).toBe('oidc-path');
      }
    });
  });

  describe('given HTTP 500 status from all URLs', () => {
    it('fetchDiscoveryDocumentWithFallback_Http500All_ReturnsError', async () => {
      // Arrange
      const urls = buildDiscoveryUrls(TEST_AM_URL, TEST_REALM_PATH);
      const httpClient = createStatusHttpClient(
        {
          [urls.rfc8414]: 500,
          [urls.oidcPath]: 500,
          [urls.oidcStandard]: 500,
        },
        validDiscoveryDoc
      );

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('HTTP 500');
      }
    });
  });

  describe('given invalid discovery document from successful URL', () => {
    it('fetchDiscoveryDocumentWithFallback_InvalidDoc_TriesNextUrl', async () => {
      // Arrange - first URL returns invalid doc, second returns valid
      const urls = buildDiscoveryUrls(TEST_AM_URL, TEST_REALM_PATH);
      const invalidDoc = { issuer: TEST_ISSUER }; // Missing required fields

      const httpClient: HttpClient = {
        json: (request: { readonly url: string }) => {
          if (request.url === urls.rfc8414) {
            return Promise.resolve({
              isOk: () => true as const,
              isErr: () => false as const,
              value: { body: invalidDoc, status: 200, headers: {} },
              error: undefined as never,
            });
          }
          if (request.url === urls.oidcPath) {
            return Promise.resolve({
              isOk: () => true as const,
              isErr: () => false as const,
              value: { body: validDiscoveryDoc, status: 200, headers: {} },
              error: undefined as never,
            });
          }
          return Promise.resolve({
            isOk: () => false as const,
            isErr: () => true as const,
            value: undefined as never,
            error: { message: 'Not found', code: 'FETCH_ERROR' },
          });
        },
        form: () => Promise.reject(new Error('Not implemented')),
      };

      // Act
      const result = await fetchDiscoveryDocumentWithFallback(
        httpClient,
        TEST_AM_URL,
        TEST_REALM_PATH
      );

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.variant).toBe('oidc-path');
        expect(result.value.triedUrls).toContain(urls.rfc8414);
      }
    });
  });
});

// ============================================================================
// fetchDiscoveryDocument Tests (deprecated, kept for backwards compatibility)
// ============================================================================

/* eslint-disable @typescript-eslint/no-deprecated -- Testing deprecated function for backwards compatibility */
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
/* eslint-enable @typescript-eslint/no-deprecated */

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

  describe('getLastSuccessfulUrl', () => {
    it('createCachedDiscoveryFetcher_AfterFetch_ReturnsLastSuccessfulUrl', async () => {
      // Arrange
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

      // Act
      await fetcher.fetch();

      // Assert
      expect(fetcher.getLastSuccessfulUrl()).toBeDefined();
    });

    it('createCachedDiscoveryFetcher_BeforeFetch_ReturnsUndefined', () => {
      // Arrange
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

      // Act & Assert
      expect(fetcher.getLastSuccessfulUrl()).toBeUndefined();
    });
  });

  describe('getLastSuccessfulVariant', () => {
    it('createCachedDiscoveryFetcher_AfterFetch_ReturnsLastSuccessfulVariant', async () => {
      // Arrange
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

      // Act
      await fetcher.fetch();

      // Assert
      expect(fetcher.getLastSuccessfulVariant()).toBeDefined();
    });
  });

  describe('useFallbackChain option', () => {
    it('createCachedDiscoveryFetcher_UseFallbackChainFalse_UsesLegacyFetch', async () => {
      // Arrange
      const discoveryDoc = createDiscoveryDocument();
      const httpClient = createSuccessHttpClient(discoveryDoc);
      const cache = createMockCache();

      const fetcher = createCachedDiscoveryFetcher(
        httpClient,
        cache,
        TEST_AM_URL,
        TEST_REALM_PATH,
        ONE_HOUR_MS,
        { useFallbackChain: false }
      );

      // Act
      const result = await fetcher.fetch();

      // Assert
      expect(result.isOk()).toBe(true);
      // Legacy fetch uses OIDC standard format
      expect(fetcher.getLastSuccessfulVariant()).toBe('oidc-standard');
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
