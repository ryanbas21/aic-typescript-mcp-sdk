import { describe, it, expect } from 'vitest';
import { parseScopes, getMissingScopes } from './scopes.js';
import {
  SCOPE_READ,
  SCOPE_WRITE,
  SCOPE_DELETE,
  SCOPE_ADMIN,
  SCOPES_READ_WRITE,
} from '../test/fixtures.js';

describe('parseScopes', () => {
  describe('given undefined input', () => {
    it('returns empty array', () => {
      const result = parseScopes(undefined);

      expect(result).toEqual([]);
    });
  });

  describe('given empty string', () => {
    it('returns empty array', () => {
      const result = parseScopes('');

      expect(result).toEqual([]);
    });
  });

  describe('given whitespace-only string', () => {
    it('returns empty array', () => {
      const result = parseScopes('   ');

      expect(result).toEqual([]);
    });
  });

  describe('given single scope', () => {
    it('returns array with one scope', () => {
      const result = parseScopes(SCOPE_READ);

      expect(result).toEqual([SCOPE_READ]);
    });
  });

  describe('given multiple space-separated scopes', () => {
    it('returns array with all scopes', () => {
      const result = parseScopes(SCOPES_READ_WRITE);

      expect(result).toEqual([SCOPE_READ, SCOPE_WRITE]);
    });
  });

  describe('given scopes with extra whitespace', () => {
    it('trims whitespace and returns clean scopes', () => {
      const scopeWithExtraSpaces = `  ${SCOPE_READ}   ${SCOPE_WRITE}  `;

      const result = parseScopes(scopeWithExtraSpaces);

      expect(result).toEqual([SCOPE_READ, SCOPE_WRITE]);
    });
  });

  describe('given scopes with multiple spaces between them', () => {
    it('ignores empty segments from multiple spaces', () => {
      const scopeWithMultipleSpaces = `${SCOPE_READ}    ${SCOPE_WRITE}`;

      const result = parseScopes(scopeWithMultipleSpaces);

      expect(result).toEqual([SCOPE_READ, SCOPE_WRITE]);
    });
  });
});

describe('getMissingScopes', () => {
  describe('given empty required scopes', () => {
    it('returns empty array regardless of present scopes', () => {
      const requiredScopes: readonly string[] = [];
      const presentScopes = [SCOPE_READ, SCOPE_WRITE];

      const result = getMissingScopes(requiredScopes, presentScopes);

      expect(result).toEqual([]);
    });
  });

  describe('given empty present scopes', () => {
    it('returns all required scopes as missing', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE];
      const presentScopes: readonly string[] = [];

      const result = getMissingScopes(requiredScopes, presentScopes);

      expect(result).toEqual([SCOPE_READ, SCOPE_WRITE]);
    });
  });

  describe('given all required scopes are present', () => {
    it('returns empty array', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE];
      const presentScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_DELETE];

      const result = getMissingScopes(requiredScopes, presentScopes);

      expect(result).toEqual([]);
    });
  });

  describe('given some required scopes are missing', () => {
    it('returns only the missing scopes', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];
      const presentScopes = [SCOPE_READ, SCOPE_DELETE];

      const result = getMissingScopes(requiredScopes, presentScopes);

      expect(result).toEqual([SCOPE_WRITE, SCOPE_ADMIN]);
    });
  });

  describe('given exact match of required and present scopes', () => {
    it('returns empty array', () => {
      const requiredScopes = [SCOPE_READ, SCOPE_WRITE];
      const presentScopes = [SCOPE_READ, SCOPE_WRITE];

      const result = getMissingScopes(requiredScopes, presentScopes);

      expect(result).toEqual([]);
    });
  });

  describe('given no required scopes and no present scopes', () => {
    it('returns empty array', () => {
      const requiredScopes: readonly string[] = [];
      const presentScopes: readonly string[] = [];

      const result = getMissingScopes(requiredScopes, presentScopes);

      expect(result).toEqual([]);
    });
  });
});
