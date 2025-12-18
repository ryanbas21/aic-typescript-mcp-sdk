import { describe, it, expect } from 'vitest';
import { AuthenticationError, AuthorizationError } from './types.js';
import {
  createAuthenticationInfo,
  SCOPE_READ,
  SCOPE_WRITE,
  SCOPE_ADMIN,
} from '../test/fixtures.js';

describe('AuthenticationError', () => {
  describe('given validation failure without auth info', () => {
    it('creates error with code and message', () => {
      const failure = {
        valid: false as const,
        error: 'EXPIRED_TOKEN' as const,
        message: 'Token has expired',
      };

      const error = new AuthenticationError(failure);

      expect(error.name).toBe('AuthenticationError');
      expect(error.code).toBe('EXPIRED_TOKEN');
      expect(error.message).toBe('Token has expired');
      expect(error.authenticationInfo).toBeUndefined();
    });
  });

  describe('given validation failure with auth info', () => {
    it('includes authentication info', () => {
      const authInfo = createAuthenticationInfo();
      const failure = {
        valid: false as const,
        error: 'MISSING_TOKEN' as const,
        message: 'No access token provided',
        authenticationInfo: authInfo,
      };

      const error = new AuthenticationError(failure);

      expect(error.authenticationInfo).toEqual(authInfo);
    });
  });

  it('is an instance of Error', () => {
    const failure = {
      valid: false as const,
      error: 'MALFORMED_TOKEN' as const,
      message: 'Invalid token',
    };

    const error = new AuthenticationError(failure);

    expect(error).toBeInstanceOf(Error);
  });

  it('has httpStatusCode of 401', () => {
    const failure = {
      valid: false as const,
      error: 'MISSING_TOKEN' as const,
      message: 'No token',
    };

    const error = new AuthenticationError(failure);

    expect(error.httpStatusCode).toBe(401);
  });
});

describe('AuthorizationError', () => {
  describe('given missing scopes', () => {
    it('creates error with missing scopes in message', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];
      const presentScopes = [SCOPE_READ];

      const error = new AuthorizationError(requiredScopes, presentScopes);

      expect(error.name).toBe('AuthorizationError');
      expect(error.message).toContain(SCOPE_WRITE);
      expect(error.message).toContain(SCOPE_ADMIN);
      expect(error.message).not.toContain(SCOPE_READ); // Present scope not in missing
    });
  });

  it('stores required and present scopes', () => {
    const requiredScopes = [SCOPE_READ, SCOPE_WRITE];
    const presentScopes = [SCOPE_READ];

    const error = new AuthorizationError(requiredScopes, presentScopes);

    expect(error.requiredScopes).toEqual(requiredScopes);
    expect(error.presentScopes).toEqual(presentScopes);
  });

  it('computes missingScopes correctly', () => {
    const requiredScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];
    const presentScopes = [SCOPE_READ];

    const error = new AuthorizationError(requiredScopes, presentScopes);

    expect(error.missingScopes).toEqual([SCOPE_WRITE, SCOPE_ADMIN]);
  });

  it('has httpStatusCode of 403', () => {
    const error = new AuthorizationError([SCOPE_READ], []);

    expect(error.httpStatusCode).toBe(403);
  });

  it('is an instance of Error', () => {
    const error = new AuthorizationError([SCOPE_READ], []);

    expect(error).toBeInstanceOf(Error);
  });
});
