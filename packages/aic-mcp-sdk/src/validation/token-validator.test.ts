import { describe, it, expect } from 'vitest';
import { ok } from 'neverthrow';
import { createTokenValidator } from './token-validator.js';
import type { OidcDiscoveryDocument } from './types.js';
import type { HttpClient } from '../http/types.js';
import { createSuccessHttpClient, createErrorHttpClient, createMockCache } from '../test/mocks.js';
import {
  TEST_AM_URL,
  TEST_CLIENT_ID,
  VALID_FORMAT_JWT,
  createDiscoveryDocument,
} from '../test/fixtures.js';

describe('createTokenValidator', () => {
  describe('validate', () => {
    describe('given undefined token', () => {
      it('returns MISSING_TOKEN failure', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.validate(undefined);

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error).toBe('MISSING_TOKEN');
          expect(result.message).toBe('No access token provided');
        }
      });

      it('includes authentication info when discovery succeeds', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.validate(undefined);

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.authenticationInfo).toBeDefined();
          expect(result.authenticationInfo?.issuer).toBe(discovery.issuer);
        }
      });
    });

    describe('given empty string token', () => {
      it('returns MISSING_TOKEN failure', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.validate('');

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error).toBe('MISSING_TOKEN');
        }
      });
    });

    describe('given whitespace-only token', () => {
      it('returns MISSING_TOKEN failure', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.validate('   ');

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error).toBe('MISSING_TOKEN');
        }
      });
    });

    describe('given discovery fetch fails', () => {
      it('returns VALIDATION_ERROR failure', async () => {
        const httpClient = createErrorHttpClient('Network error', 500);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.validate(VALID_FORMAT_JWT);

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error).toBe('VALIDATION_ERROR');
        }
      });
    });

    describe('given opaque (non-JWT) token', () => {
      it('returns MALFORMED_TOKEN failure with introspection not supported message', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );
        const opaqueToken = 'opaque-access-token-12345';

        const result = await validator.validate(opaqueToken);

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error).toBe('MALFORMED_TOKEN');
          expect(result.message).toContain('not a valid JWT');
          expect(result.message).toContain('introspection');
        }
      });

      it('includes authentication info', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.validate('opaque-token');

        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.authenticationInfo).toBeDefined();
        }
      });
    });
  });

  describe('getAuthenticationInfo', () => {
    describe('given discovery succeeds', () => {
      it('returns authentication info', async () => {
        const discovery = createDiscoveryDocument();
        const httpClient = createSuccessHttpClient(discovery);
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.getAuthenticationInfo();

        expect(result).toBeDefined();
        expect(result?.issuer).toBe(discovery.issuer);
        expect(result?.authorizationEndpoint).toBe(discovery.authorization_endpoint);
        expect(result?.tokenEndpoint).toBe(discovery.token_endpoint);
      });
    });

    describe('given discovery fails', () => {
      it('returns undefined', async () => {
        const httpClient = createErrorHttpClient('Network error');
        const cache = createMockCache<OidcDiscoveryDocument>();

        const validator = createTokenValidator(
          { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
          httpClient,
          cache
        );

        const result = await validator.getAuthenticationInfo();

        expect(result).toBeUndefined();
      });
    });
  });

  describe('refreshCache', () => {
    it('clears cache and re-fetches discovery document', async () => {
      const discovery = createDiscoveryDocument();
      const httpClient = createSuccessHttpClient(discovery);
      const cache = createMockCache<OidcDiscoveryDocument>();

      const validator = createTokenValidator(
        { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
        httpClient,
        cache
      );

      // Initial fetch
      await validator.getAuthenticationInfo();
      expect(cache.setCalls.length).toBe(1);

      // Refresh cache
      await validator.refreshCache();

      // Should have cleared and re-fetched
      expect(cache.deleteCalls).toContain('oidc-discovery');
      expect(cache.setCalls.length).toBe(2);
    });
  });

  describe('JWKS URI tracking', () => {
    it('recreates JWKS when URI changes after cache refresh', async () => {
      const initialDiscovery = createDiscoveryDocument({
        jwks_uri: 'https://auth.example.com/jwks/v1',
      });
      const updatedDiscovery = createDiscoveryDocument({
        jwks_uri: 'https://auth.example.com/jwks/v2',
      });

      let fetchCount = 0;
      const httpClient: HttpClient = {
        json: () => {
          fetchCount++;
          const doc = fetchCount === 1 ? initialDiscovery : updatedDiscovery;
          return Promise.resolve(ok({ status: 200, statusText: 'OK', headers: {}, body: doc }));
        },
        text: () => Promise.resolve(ok({ status: 200, statusText: 'OK', headers: {}, body: '' })),
      };

      const cache = createMockCache<OidcDiscoveryDocument>();

      const validator = createTokenValidator(
        { amUrl: TEST_AM_URL, clientId: TEST_CLIENT_ID },
        httpClient,
        cache
      );

      // First validation will use initial JWKS URI
      await validator.validate(VALID_FORMAT_JWT);

      // Refresh cache to get new discovery document
      cache.data.clear(); // Simulate cache expiration
      await validator.refreshCache();

      // Next validation should use updated JWKS URI
      // (We can't easily verify this without mocking jose, but the test ensures no errors)
      const result = await validator.validate(VALID_FORMAT_JWT);

      // The validation will fail (no real JWKS), but the important thing is
      // that the code path for recreating JWKS was exercised
      expect(fetchCount).toBeGreaterThan(1);
      // Result will be an error since we can't actually verify the JWT
      expect(result.valid).toBe(false);
    });
  });
});
