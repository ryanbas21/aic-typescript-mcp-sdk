import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createWithAuth } from './with-auth.js';
import { AuthenticationError, AuthorizationError } from './types.js';
import type { TokenValidator } from '../validation/types.js';
import type { TokenValidationResult, TokenClaims } from '../types.js';
import {
  TEST_SUBJECT,
  TEST_ISSUER,
  TEST_AUDIENCE,
  TEST_CLIENT_ID,
  SCOPE_READ,
  SCOPE_WRITE,
  SCOPE_ADMIN,
  SCOPES_READ_WRITE,
  FIXED_TIMESTAMP_SECONDS,
  ONE_HOUR_MS,
  createAuthenticationInfo,
} from '../test/fixtures.js';

// ============================================================================
// Test Helpers
// ============================================================================

const createMockValidator = (
  validateResult: TokenValidationResult,
  authInfo = createAuthenticationInfo()
): TokenValidator => ({
  validate: vi.fn().mockResolvedValue(validateResult),
  getAuthenticationInfo: vi.fn().mockResolvedValue(authInfo),
  refreshCache: vi.fn().mockResolvedValue(undefined),
});

const createSuccessResult = (claims: Partial<TokenClaims> = {}): TokenValidationResult => ({
  valid: true,
  claims: {
    sub: TEST_SUBJECT,
    iss: TEST_ISSUER,
    aud: TEST_AUDIENCE,
    exp: FIXED_TIMESTAMP_SECONDS + ONE_HOUR_MS / 1000,
    iat: FIXED_TIMESTAMP_SECONDS,
    scope: SCOPES_READ_WRITE,
    client_id: TEST_CLIENT_ID,
    ...claims,
  },
  accessToken: 'test-token',
});

const createFailureResult = (
  error: 'MISSING_TOKEN' | 'EXPIRED_TOKEN' | 'INVALID_SIGNATURE',
  message: string
): TokenValidationResult => ({
  valid: false,
  error,
  message,
  authenticationInfo: createAuthenticationInfo(),
});

/** Environment variable for access token */
const ENV_VAR_NAME = 'AM_ACCESS_TOKEN';

// ============================================================================
// Tests
// ============================================================================

describe('createWithAuth', () => {
  beforeEach(() => {
    vi.stubEnv(ENV_VAR_NAME, undefined);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe('token extraction', () => {
    describe('given token in _meta', () => {
      it('extracts token from _meta.accessToken', async () => {
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);

        await wrappedHandler({}, { _meta: { accessToken: 'meta-token' } });

        expect(validator.validate).toHaveBeenCalledWith('meta-token', {});
      });
    });

    describe('given token in environment variable', () => {
      it('extracts token from env var', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'env-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);

        await wrappedHandler({}, {});

        expect(validator.validate).toHaveBeenCalledWith('env-token', {});
      });
    });

    describe('given token in both _meta and env', () => {
      it('prefers _meta token (default: both)', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'env-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);

        await wrappedHandler({}, { _meta: { accessToken: 'meta-token' } });

        expect(validator.validate).toHaveBeenCalledWith('meta-token', {});
      });
    });

    describe('given stdioTokenSource: "env"', () => {
      it('only uses environment variable', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'env-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({
          validator,
          tokenExtractor: { stdioTokenSource: 'env' },
        });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);

        await wrappedHandler({}, { _meta: { accessToken: 'meta-token' } });

        expect(validator.validate).toHaveBeenCalledWith('env-token', {});
      });
    });

    describe('given stdioTokenSource: "meta"', () => {
      it('only uses _meta field', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'env-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({
          validator,
          tokenExtractor: { stdioTokenSource: 'meta' },
        });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);

        await wrappedHandler({}, { _meta: { accessToken: 'meta-token' } });

        expect(validator.validate).toHaveBeenCalledWith('meta-token', {});
      });

      it('returns undefined when _meta has no token', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'env-token');
        const authInfo = createAuthenticationInfo();
        const validator = createMockValidator(
          createFailureResult('MISSING_TOKEN', 'No token'),
          authInfo
        );
        const withAuth = createWithAuth({
          validator,
          tokenExtractor: { stdioTokenSource: 'meta' },
        });
        const handler = vi.fn();
        const wrappedHandler = withAuth({}, handler);

        await expect(wrappedHandler({}, {})).rejects.toThrow(AuthenticationError);
        expect(handler).not.toHaveBeenCalled();
      });
    });

    describe('given custom token extractor function', () => {
      it('uses the custom function', async () => {
        const customExtractor = vi.fn().mockReturnValue('custom-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({
          validator,
          tokenExtractor: { stdioTokenSource: customExtractor },
        });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);
        const extra = { _meta: { accessToken: 'ignored' } };

        await wrappedHandler({}, extra);

        expect(customExtractor).toHaveBeenCalledWith(extra);
        expect(validator.validate).toHaveBeenCalledWith('custom-token', {});
      });
    });

    describe('given no token available', () => {
      it('throws AuthenticationError', async () => {
        const authInfo = createAuthenticationInfo();
        const validator = createMockValidator(
          createFailureResult('MISSING_TOKEN', 'No token'),
          authInfo
        );
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn();
        const wrappedHandler = withAuth({}, handler);

        await expect(wrappedHandler({}, {})).rejects.toThrow(AuthenticationError);
      });

      it('includes authentication info in error', async () => {
        const authInfo = createAuthenticationInfo();
        const validator = createMockValidator(
          createFailureResult('MISSING_TOKEN', 'No token'),
          authInfo
        );
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn();
        const wrappedHandler = withAuth({}, handler);

        try {
          await wrappedHandler({}, {});
          expect.fail('Should have thrown');
        } catch (error) {
          expect(error).toBeInstanceOf(AuthenticationError);
          expect((error as AuthenticationError).authenticationInfo).toEqual(authInfo);
        }
      });
    });
  });

  describe('validation', () => {
    describe('given token validation fails', () => {
      it('throws AuthenticationError', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'invalid-token');
        const validator = createMockValidator(
          createFailureResult('EXPIRED_TOKEN', 'Token expired')
        );
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn();
        const wrappedHandler = withAuth({}, handler);

        await expect(wrappedHandler({}, {})).rejects.toThrow(AuthenticationError);
        expect(handler).not.toHaveBeenCalled();
      });

      it('error has correct code from validation result', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'invalid-token');
        const validator = createMockValidator(
          createFailureResult('INVALID_SIGNATURE', 'Bad signature')
        );
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn();
        const wrappedHandler = withAuth({}, handler);

        try {
          await wrappedHandler({}, {});
          expect.fail('Should have thrown');
        } catch (error) {
          expect((error as AuthenticationError).code).toBe('INVALID_SIGNATURE');
        }
      });
    });

    describe('given token validation succeeds', () => {
      it('calls handler with authInfo', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'valid-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);

        await wrappedHandler({ arg: 'value' }, {});

        expect(handler).toHaveBeenCalled();
        const [, extra] = handler.mock.calls[0] as [
          unknown,
          { authInfo: { token: string; clientId: string; scopes: string[] } },
        ];
        expect(extra.authInfo.token).toBe('valid-token');
        expect(extra.authInfo.clientId).toBe(TEST_CLIENT_ID);
        expect(extra.authInfo.scopes).toEqual([SCOPE_READ, SCOPE_WRITE]);
      });

      it('returns handler result', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'valid-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const expectedResult = { content: [{ type: 'text' as const, text: 'Hello' }] };
        const handler = vi.fn().mockResolvedValue(expectedResult);
        const wrappedHandler = withAuth({}, handler);

        const result: unknown = await wrappedHandler({}, {});

        expect(result).toEqual(expectedResult);
      });
    });
  });

  describe('scope validation', () => {
    describe('given required scopes and token has them', () => {
      it('calls handler successfully', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'valid-token');
        const validator = createMockValidator(
          createSuccessResult({ scope: `${SCOPE_READ} ${SCOPE_WRITE}` })
        );
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({ requiredScopes: [SCOPE_READ] }, handler);

        await wrappedHandler({}, {});

        expect(handler).toHaveBeenCalled();
      });

      it('passes requiredScopes to validator', async () => {
        vi.stubEnv(ENV_VAR_NAME, 'valid-token');
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const requiredScopes = [SCOPE_READ, SCOPE_WRITE];
        const wrappedHandler = withAuth({ requiredScopes }, handler);

        await wrappedHandler({}, {});

        expect(validator.validate).toHaveBeenCalledWith('valid-token', { requiredScopes });
      });
    });
  });

  describe('existing authInfo', () => {
    describe('given authInfo already in extra', () => {
      it('uses existing authInfo without re-validating', async () => {
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn().mockResolvedValue({ result: 'success' });
        const wrappedHandler = withAuth({}, handler);
        const existingAuthInfo = {
          token: 'existing-token',
          clientId: 'existing-client',
          scopes: [SCOPE_READ],
          expiresAt: FIXED_TIMESTAMP_SECONDS + 3600,
        };

        await wrappedHandler({}, { authInfo: existingAuthInfo });

        expect(validator.validate).not.toHaveBeenCalled();
        expect(handler).toHaveBeenCalledWith(
          {},
          expect.objectContaining({ authInfo: existingAuthInfo })
        );
      });
    });

    describe('given authInfo exists but required scopes are missing', () => {
      it('throws AuthorizationError', async () => {
        const validator = createMockValidator(createSuccessResult());
        const withAuth = createWithAuth({ validator });
        const handler = vi.fn();
        const wrappedHandler = withAuth({ requiredScopes: [SCOPE_ADMIN] }, handler);
        const existingAuthInfo = {
          token: 'existing-token',
          clientId: 'existing-client',
          scopes: [SCOPE_READ],
        };

        await expect(wrappedHandler({}, { authInfo: existingAuthInfo })).rejects.toThrow(
          AuthorizationError
        );
        expect(handler).not.toHaveBeenCalled();
      });
    });
  });
});
