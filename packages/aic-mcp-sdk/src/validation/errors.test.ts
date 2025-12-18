import { describe, it, expect } from 'vitest';
import {
  createValidationFailure,
  createMissingTokenFailure,
  createInsufficientScopeFailure,
  mapJoseError,
  createNetworkError,
  createDiscoveryError,
  createJwksError,
  createIntrospectionError,
} from './errors.js';
import type { ValidationError } from './types.js';
import {
  createAuthenticationInfo,
  SCOPE_READ,
  SCOPE_WRITE,
  SCOPE_ADMIN,
} from '../test/fixtures.js';

describe('createValidationFailure', () => {
  describe('given a validation error without auth info', () => {
    it('returns failure with mapped error code and message', () => {
      const validationError: ValidationError = {
        code: 'EXPIRED_TOKEN',
        message: 'Token expired at 12:00',
      };

      const result = createValidationFailure(validationError);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('EXPIRED_TOKEN');
      expect(result.message).toBe('Token expired at 12:00');
      expect(result.authenticationInfo).toBeUndefined();
    });
  });

  describe('given a validation error with auth info', () => {
    it('includes authentication info in the result', () => {
      const validationError: ValidationError = {
        code: 'INVALID_SIGNATURE',
        message: 'Signature mismatch',
      };
      const authInfo = createAuthenticationInfo();

      const result = createValidationFailure(validationError, authInfo);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('INVALID_SIGNATURE');
      expect(result.authenticationInfo).toEqual(authInfo);
    });
  });

  describe('given an internal error code that maps to VALIDATION_ERROR', () => {
    it('maps DISCOVERY_ERROR to VALIDATION_ERROR', () => {
      const validationError: ValidationError = {
        code: 'DISCOVERY_ERROR',
        message: 'Failed to fetch discovery',
      };

      const result = createValidationFailure(validationError);

      expect(result.error).toBe('VALIDATION_ERROR');
    });

    it('maps JWKS_ERROR to VALIDATION_ERROR', () => {
      const validationError: ValidationError = {
        code: 'JWKS_ERROR',
        message: 'Failed to fetch JWKS',
      };

      const result = createValidationFailure(validationError);

      expect(result.error).toBe('VALIDATION_ERROR');
    });

    it('maps NETWORK_ERROR to VALIDATION_ERROR', () => {
      const validationError: ValidationError = {
        code: 'NETWORK_ERROR',
        message: 'Connection refused',
      };

      const result = createValidationFailure(validationError);

      expect(result.error).toBe('VALIDATION_ERROR');
    });
  });

  describe('given validation error without message', () => {
    it('uses default message for the error code', () => {
      const validationError: ValidationError = {
        code: 'EXPIRED_TOKEN',
        message: '',
      };

      const result = createValidationFailure(validationError);

      expect(result.message).toBe('Token has expired');
    });
  });
});

describe('createMissingTokenFailure', () => {
  describe('given no auth info', () => {
    it('returns missing token failure without auth info', () => {
      const result = createMissingTokenFailure();

      expect(result.valid).toBe(false);
      expect(result.error).toBe('MISSING_TOKEN');
      expect(result.message).toBe('No access token provided');
      expect(result.authenticationInfo).toBeUndefined();
    });
  });

  describe('given auth info', () => {
    it('includes authentication info in the result', () => {
      const authInfo = createAuthenticationInfo();

      const result = createMissingTokenFailure(authInfo);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('MISSING_TOKEN');
      expect(result.authenticationInfo).toEqual(authInfo);
    });
  });
});

describe('createInsufficientScopeFailure', () => {
  describe('given missing scopes without auth info', () => {
    it('returns failure with list of missing scopes', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];
      const presentScopes = [SCOPE_READ];

      const result = createInsufficientScopeFailure(requiredScopes, presentScopes);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('INSUFFICIENT_SCOPE');
      expect(result.message).toBe(`Missing required scopes: ${SCOPE_WRITE}, ${SCOPE_ADMIN}`);
      expect(result.authenticationInfo).toBeUndefined();
    });
  });

  describe('given missing scopes with auth info', () => {
    it('includes authentication info in the result', () => {
      const requiredScopes = [SCOPE_WRITE];
      const presentScopes: string[] = [];
      const authInfo = createAuthenticationInfo();

      const result = createInsufficientScopeFailure(requiredScopes, presentScopes, authInfo);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('INSUFFICIENT_SCOPE');
      expect(result.authenticationInfo).toEqual(authInfo);
    });
  });
});

describe('mapJoseError', () => {
  describe('given JWTExpired error', () => {
    it('maps to EXPIRED_TOKEN', () => {
      const joseError = new Error('Token expired');
      joseError.name = 'JWTExpired';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('EXPIRED_TOKEN');
      expect(result.message).toBe('Token has expired');
      expect(result.cause).toBe(joseError);
    });
  });

  describe('given JWTClaimValidationFailed with iss in message', () => {
    it('maps to INVALID_ISSUER', () => {
      const joseError = new Error('unexpected "iss" claim value');
      joseError.name = 'JWTClaimValidationFailed';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('INVALID_ISSUER');
      expect(result.message).toBe('Token issuer is invalid');
    });
  });

  describe('given JWTClaimValidationFailed with aud in message', () => {
    it('maps to INVALID_AUDIENCE', () => {
      const joseError = new Error('unexpected "aud" claim value');
      joseError.name = 'JWTClaimValidationFailed';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('INVALID_AUDIENCE');
      expect(result.message).toBe('Token audience is invalid');
    });
  });

  describe('given JWTClaimValidationFailed with other claim', () => {
    it('maps to MALFORMED_TOKEN with original message', () => {
      const joseError = new Error('unexpected "nbf" claim value');
      joseError.name = 'JWTClaimValidationFailed';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('MALFORMED_TOKEN');
      expect(result.message).toBe('unexpected "nbf" claim value');
    });
  });

  describe('given JWSSignatureVerificationFailed error', () => {
    it('maps to INVALID_SIGNATURE', () => {
      const joseError = new Error('Signature mismatch');
      joseError.name = 'JWSSignatureVerificationFailed';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('INVALID_SIGNATURE');
      expect(result.message).toBe('Token signature verification failed');
    });
  });

  describe('given JWSInvalid error', () => {
    it('maps to MALFORMED_TOKEN', () => {
      const joseError = new Error('Invalid JWS');
      joseError.name = 'JWSInvalid';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('MALFORMED_TOKEN');
      expect(result.message).toBe('Token format is invalid');
    });
  });

  describe('given JWTInvalid error', () => {
    it('maps to MALFORMED_TOKEN', () => {
      const joseError = new Error('Invalid JWT');
      joseError.name = 'JWTInvalid';

      const result = mapJoseError(joseError);

      expect(result.code).toBe('MALFORMED_TOKEN');
      expect(result.message).toBe('Token format is invalid');
    });
  });

  describe('given unknown Error type', () => {
    it('maps to MALFORMED_TOKEN with original message', () => {
      const unknownError = new Error('Something went wrong');

      const result = mapJoseError(unknownError);

      expect(result.code).toBe('MALFORMED_TOKEN');
      expect(result.message).toBe('Something went wrong');
      expect(result.cause).toBe(unknownError);
    });
  });

  describe('given non-Error value', () => {
    it('maps to MALFORMED_TOKEN with generic message', () => {
      const nonError = { some: 'object' };

      const result = mapJoseError(nonError);

      expect(result.code).toBe('MALFORMED_TOKEN');
      expect(result.message).toBe('Unknown token validation error');
      expect(result.cause).toBe(nonError);
    });
  });
});

describe('error factory functions', () => {
  describe('createNetworkError', () => {
    it('creates NETWORK_ERROR with message and cause', () => {
      const cause = new Error('Connection timeout');

      const result = createNetworkError('Failed to connect', cause);

      expect(result.code).toBe('NETWORK_ERROR');
      expect(result.message).toBe('Failed to connect');
      expect(result.cause).toBe(cause);
    });
  });

  describe('createDiscoveryError', () => {
    it('creates DISCOVERY_ERROR with message and cause', () => {
      const cause = new Error('404');

      const result = createDiscoveryError('Discovery endpoint not found', cause);

      expect(result.code).toBe('DISCOVERY_ERROR');
      expect(result.message).toBe('Discovery endpoint not found');
      expect(result.cause).toBe(cause);
    });
  });

  describe('createJwksError', () => {
    it('creates JWKS_ERROR with message and cause', () => {
      const cause = new Error('Invalid JWKS format');

      const result = createJwksError('Failed to parse JWKS', cause);

      expect(result.code).toBe('JWKS_ERROR');
      expect(result.message).toBe('Failed to parse JWKS');
      expect(result.cause).toBe(cause);
    });
  });

  describe('createIntrospectionError', () => {
    it('creates INTROSPECTION_ERROR with message and cause', () => {
      const cause = new Error('401 Unauthorized');

      const result = createIntrospectionError('Introspection request failed', cause);

      expect(result.code).toBe('INTROSPECTION_ERROR');
      expect(result.message).toBe('Introspection request failed');
      expect(result.cause).toBe(cause);
    });
  });
});
