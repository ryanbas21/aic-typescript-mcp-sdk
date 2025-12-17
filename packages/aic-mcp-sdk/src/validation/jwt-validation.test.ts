import { describe, it, expect } from 'vitest';
import { isJwtFormat, validateScopes, toTokenClaims, validateJwtClaims } from './jwt-validation.js';
import type { ValidatedJwtClaims } from './types.js';
import {
  VALID_FORMAT_JWT,
  VALID_JWT_HEADER,
  SAMPLE_JWT_PAYLOAD,
  SCOPE_READ,
  SCOPE_WRITE,
  SCOPE_ADMIN,
  SCOPES_READ_WRITE,
  TEST_SUBJECT,
  TEST_ISSUER,
  TEST_AUDIENCE,
  TEST_JWT_ID,
  TEST_CLIENT_ID,
  FIXED_TIMESTAMP_SECONDS,
  ONE_HOUR_MS,
} from '../test/fixtures.js';

// ============================================================================
// isJwtFormat Tests
// ============================================================================

describe('isJwtFormat', () => {
  describe('given valid JWT structure', () => {
    it('returns true for three base64url parts', () => {
      const result = isJwtFormat(VALID_FORMAT_JWT);

      expect(result).toBe(true);
    });

    it('returns true for tokens with underscores and hyphens', () => {
      const tokenWithSpecialChars = 'abc_def-ghi.jkl_mno-pqr.stu_vwx-yz0';

      const result = isJwtFormat(tokenWithSpecialChars);

      expect(result).toBe(true);
    });
  });

  describe('given invalid JWT structure', () => {
    it('returns false for empty string', () => {
      const result = isJwtFormat('');

      expect(result).toBe(false);
    });

    it('returns false for single part', () => {
      const result = isJwtFormat(VALID_JWT_HEADER);

      expect(result).toBe(false);
    });

    it('returns false for two parts', () => {
      const result = isJwtFormat(`${VALID_JWT_HEADER}.${SAMPLE_JWT_PAYLOAD}`);

      expect(result).toBe(false);
    });

    it('returns false for four parts', () => {
      const result = isJwtFormat(`${VALID_FORMAT_JWT}.extra`);

      expect(result).toBe(false);
    });

    it('returns false for empty parts', () => {
      const result = isJwtFormat('header..signature');

      expect(result).toBe(false);
    });

    it('returns false for non-base64url characters', () => {
      const result = isJwtFormat('header!invalid.payload.signature');

      expect(result).toBe(false);
    });

    it('returns false for parts with spaces', () => {
      const result = isJwtFormat('header with space.payload.signature');

      expect(result).toBe(false);
    });

    it('returns false for opaque tokens', () => {
      const opaqueToken = 'SSo1234567890abcdefghijklmnop';

      const result = isJwtFormat(opaqueToken);

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// validateScopes Tests
// ============================================================================

describe('validateScopes', () => {
  describe('given all required scopes are present', () => {
    it('returns Ok with present scopes', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE];
      const presentScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];

      const result = validateScopes(requiredScopes, presentScopes);

      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value).toEqual(presentScopes);
      }
    });
  });

  describe('given some required scopes are missing', () => {
    it('returns Err with INSUFFICIENT_SCOPE code', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];
      const presentScopes = [SCOPE_READ];

      const result = validateScopes(requiredScopes, presentScopes);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INSUFFICIENT_SCOPE');
        expect(result.error.message).toContain(SCOPE_WRITE);
        expect(result.error.message).toContain(SCOPE_ADMIN);
      }
    });
  });

  describe('given empty required scopes', () => {
    it('returns Ok with present scopes', () => {
      const requiredScopes: string[] = [];
      const presentScopes = [SCOPE_READ];

      const result = validateScopes(requiredScopes, presentScopes);

      expect(result.isOk()).toBe(true);
    });
  });
});

// ============================================================================
// toTokenClaims Tests
// ============================================================================

describe('toTokenClaims', () => {
  const createTestClaims = (overrides: Partial<ValidatedJwtClaims> = {}): ValidatedJwtClaims => ({
    sub: TEST_SUBJECT,
    iss: TEST_ISSUER,
    aud: TEST_AUDIENCE,
    exp: FIXED_TIMESTAMP_SECONDS + ONE_HOUR_MS / 1000,
    iat: FIXED_TIMESTAMP_SECONDS,
    ...overrides,
  });

  describe('given claims with required fields only', () => {
    it('returns TokenClaims with required fields', () => {
      const claims = createTestClaims();

      const result = toTokenClaims(claims);

      expect(result.sub).toBe(TEST_SUBJECT);
      expect(result.iss).toBe(TEST_ISSUER);
      expect(result.aud).toBe(TEST_AUDIENCE);
      expect(result.exp).toBe(claims.exp);
      expect(result.iat).toBe(claims.iat);
    });
  });

  describe('given claims with optional standard fields', () => {
    it('includes jti when present', () => {
      const claims = createTestClaims({ jti: TEST_JWT_ID });

      const result = toTokenClaims(claims);

      expect(result.jti).toBe(TEST_JWT_ID);
    });

    it('includes scope when present', () => {
      const claims = createTestClaims({ scope: SCOPES_READ_WRITE });

      const result = toTokenClaims(claims);

      expect(result.scope).toBe(SCOPES_READ_WRITE);
    });

    it('includes client_id when present', () => {
      const claims = createTestClaims({ client_id: TEST_CLIENT_ID });

      const result = toTokenClaims(claims);

      expect(result.client_id).toBe(TEST_CLIENT_ID);
    });
  });

  describe('given claims with custom fields', () => {
    it('includes custom fields in result', () => {
      const customClaimKey = 'custom_claim';
      const customClaimValue = 'custom_value';
      const claims = createTestClaims({ [customClaimKey]: customClaimValue });

      const result = toTokenClaims(claims);

      expect(result[customClaimKey]).toBe(customClaimValue);
    });
  });

  describe('given claims with array audience', () => {
    it('preserves array audience', () => {
      const audiences = ['api1.example.com', 'api2.example.com'];
      const claims = createTestClaims({ aud: audiences });

      const result = toTokenClaims(claims);

      expect(result.aud).toEqual(audiences);
    });
  });
});

// ============================================================================
// validateJwtClaims Tests
// ============================================================================

describe('validateJwtClaims', () => {
  const createTestClaims = (overrides: Partial<ValidatedJwtClaims> = {}): ValidatedJwtClaims => ({
    sub: TEST_SUBJECT,
    iss: TEST_ISSUER,
    aud: TEST_AUDIENCE,
    exp: FIXED_TIMESTAMP_SECONDS + ONE_HOUR_MS / 1000,
    iat: FIXED_TIMESTAMP_SECONDS,
    ...overrides,
  });

  describe('given no required scopes', () => {
    it('returns Ok with TokenClaims', () => {
      const claims = createTestClaims();

      const result = validateJwtClaims(claims);

      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.sub).toBe(TEST_SUBJECT);
      }
    });
  });

  describe('given required scopes and token has them', () => {
    it('returns Ok with TokenClaims', () => {
      const claims = createTestClaims({ scope: SCOPES_READ_WRITE });
      const options = { requiredScopes: [SCOPE_READ] };

      const result = validateJwtClaims(claims, options);

      expect(result.isOk()).toBe(true);
    });
  });

  describe('given required scopes and token is missing some', () => {
    it('returns Err with INSUFFICIENT_SCOPE', () => {
      const claims = createTestClaims({ scope: SCOPE_READ });
      const options = { requiredScopes: [SCOPE_READ, SCOPE_ADMIN] };

      const result = validateJwtClaims(claims, options);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INSUFFICIENT_SCOPE');
        expect(result.error.message).toContain(SCOPE_ADMIN);
      }
    });
  });

  describe('given required scopes but token has no scope claim', () => {
    it('returns Err with INSUFFICIENT_SCOPE', () => {
      const claims = createTestClaims(); // No scope claim
      const options = { requiredScopes: [SCOPE_READ] };

      const result = validateJwtClaims(claims, options);

      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INSUFFICIENT_SCOPE');
      }
    });
  });

  describe('given empty required scopes array', () => {
    it('returns Ok without checking scopes', () => {
      const claims = createTestClaims(); // No scope claim
      const options = { requiredScopes: [] };

      const result = validateJwtClaims(claims, options);

      expect(result.isOk()).toBe(true);
    });
  });
});
