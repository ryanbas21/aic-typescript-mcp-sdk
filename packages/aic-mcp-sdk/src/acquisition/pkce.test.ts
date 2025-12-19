import { describe, it, expect } from 'vitest';
import {
  generatePkceVerifier,
  createPkceChallenge,
  validatePkceChallenge,
  generatePkceChallengePair,
  verifyPkceSupport,
  requirePkceSupport,
} from './pkce.js';
import type { OidcDiscoveryDocument } from '../validation/types.js';

describe('PKCE utilities', () => {
  describe('generatePkceVerifier', () => {
    it('generatePkceVerifier_DefaultLength_Returns64CharString', () => {
      // Act
      const verifier = generatePkceVerifier();

      // Assert
      expect(verifier).toHaveLength(64);
    });

    it('generatePkceVerifier_CustomLength_ReturnsRequestedLength', () => {
      // Act
      const verifier = generatePkceVerifier(100);

      // Assert
      expect(verifier).toHaveLength(100);
    });

    it('generatePkceVerifier_LengthBelowMinimum_ClampsTo43', () => {
      // Act
      const verifier = generatePkceVerifier(10);

      // Assert
      expect(verifier).toHaveLength(43);
    });

    it('generatePkceVerifier_LengthAboveMaximum_ClampsTo128', () => {
      // Act
      const verifier = generatePkceVerifier(200);

      // Assert
      expect(verifier).toHaveLength(128);
    });

    it('generatePkceVerifier_ContainsOnlyValidCharacters', () => {
      // RFC 7636 Section 4.1: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
      const validCharsRegex = /^[A-Za-z0-9\-._~]+$/;

      // Act
      const verifier = generatePkceVerifier();

      // Assert
      expect(verifier).toMatch(validCharsRegex);
    });

    it('generatePkceVerifier_GeneratesUniqueValues', () => {
      // Act
      const verifier1 = generatePkceVerifier();
      const verifier2 = generatePkceVerifier();
      const verifier3 = generatePkceVerifier();

      // Assert
      expect(verifier1).not.toBe(verifier2);
      expect(verifier2).not.toBe(verifier3);
      expect(verifier1).not.toBe(verifier3);
    });
  });

  describe('createPkceChallenge', () => {
    it('createPkceChallenge_ValidVerifier_ReturnsChallenge', async () => {
      // Arrange
      const verifier = generatePkceVerifier();

      // Act
      const result = await createPkceChallenge(verifier);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.verifier).toBe(verifier);
        expect(result.value.method).toBe('S256');
        expect(result.value.challenge).toBeTruthy();
        // Base64url encoded SHA-256 hash should be 43 characters
        expect(result.value.challenge).toHaveLength(43);
      }
    });

    it('createPkceChallenge_VerifierTooShort_ReturnsError', async () => {
      // Arrange
      const shortVerifier = 'abc'; // Less than 43 chars

      // Act
      const result = await createPkceChallenge(shortVerifier);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('pkce_error');
        expect(result.error.message).toContain('at least 43');
      }
    });

    it('createPkceChallenge_VerifierTooLong_ReturnsError', async () => {
      // Arrange
      const longVerifier = 'a'.repeat(129); // More than 128 chars

      // Act
      const result = await createPkceChallenge(longVerifier);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('pkce_error');
        expect(result.error.message).toContain('at most 128');
      }
    });

    it('createPkceChallenge_InvalidCharacters_ReturnsError', async () => {
      // Arrange
      const invalidVerifier = 'a'.repeat(42) + '@'; // Invalid char @ at 43 length

      // Act
      const result = await createPkceChallenge(invalidVerifier);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('pkce_error');
        expect(result.error.message).toContain('invalid characters');
      }
    });

    it('createPkceChallenge_SameVerifier_ProducesSameChallenge', async () => {
      // Arrange
      const verifier = generatePkceVerifier();

      // Act
      const result1 = await createPkceChallenge(verifier);
      const result2 = await createPkceChallenge(verifier);

      // Assert
      expect(result1.isOk()).toBe(true);
      expect(result2.isOk()).toBe(true);
      if (result1.isOk() && result2.isOk()) {
        expect(result1.value.challenge).toBe(result2.value.challenge);
      }
    });

    it('createPkceChallenge_DifferentVerifiers_ProduceDifferentChallenges', async () => {
      // Arrange
      const verifier1 = generatePkceVerifier();
      const verifier2 = generatePkceVerifier();

      // Act
      const result1 = await createPkceChallenge(verifier1);
      const result2 = await createPkceChallenge(verifier2);

      // Assert
      expect(result1.isOk()).toBe(true);
      expect(result2.isOk()).toBe(true);
      if (result1.isOk() && result2.isOk()) {
        expect(result1.value.challenge).not.toBe(result2.value.challenge);
      }
    });
  });

  describe('validatePkceChallenge', () => {
    it('validatePkceChallenge_MatchingPair_ReturnsTrue', async () => {
      // Arrange
      const verifier = generatePkceVerifier();
      const challengeResult = await createPkceChallenge(verifier);
      expect(challengeResult.isOk()).toBe(true);
      if (!challengeResult.isOk()) return;

      // Act
      const isValid = await validatePkceChallenge(verifier, challengeResult.value.challenge);

      // Assert
      expect(isValid).toBe(true);
    });

    it('validatePkceChallenge_MismatchedPair_ReturnsFalse', async () => {
      // Arrange
      const verifier1 = generatePkceVerifier();
      const verifier2 = generatePkceVerifier();
      const challengeResult = await createPkceChallenge(verifier1);
      expect(challengeResult.isOk()).toBe(true);
      if (!challengeResult.isOk()) return;

      // Act - validate with different verifier
      const isValid = await validatePkceChallenge(verifier2, challengeResult.value.challenge);

      // Assert
      expect(isValid).toBe(false);
    });

    it('validatePkceChallenge_InvalidChallenge_ReturnsFalse', async () => {
      // Arrange
      const verifier = generatePkceVerifier();

      // Act
      const isValid = await validatePkceChallenge(verifier, 'invalid-challenge');

      // Assert
      expect(isValid).toBe(false);
    });
  });

  describe('generatePkceChallengePair', () => {
    it('generatePkceChallengePair_DefaultLength_ReturnsValidPair', async () => {
      // Act
      const result = await generatePkceChallengePair();

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.verifier).toHaveLength(64);
        expect(result.value.challenge).toHaveLength(43);
        expect(result.value.method).toBe('S256');
      }
    });

    it('generatePkceChallengePair_CustomLength_ReturnsValidPair', async () => {
      // Act
      const result = await generatePkceChallengePair(100);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.verifier).toHaveLength(100);
      }
    });

    it('generatePkceChallengePair_GeneratesValidatablePair', async () => {
      // Arrange
      const result = await generatePkceChallengePair();
      expect(result.isOk()).toBe(true);
      if (!result.isOk()) return;

      // Act
      const isValid = await validatePkceChallenge(result.value.verifier, result.value.challenge);

      // Assert
      expect(isValid).toBe(true);
    });
  });

  describe('verifyPkceSupport', () => {
    const createDiscoveryDoc = (
      codeChallengeMethodsSupported?: readonly string[]
    ): OidcDiscoveryDocument => ({
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/authorize',
      token_endpoint: 'https://auth.example.com/token',
      jwks_uri: 'https://auth.example.com/jwks',
      response_types_supported: ['code'],
      code_challenge_methods_supported: codeChallengeMethodsSupported,
    });

    it('verifyPkceSupport_S256Supported_ReturnsSupportedTrue', () => {
      // Arrange
      const discovery = createDiscoveryDoc(['S256']);

      // Act
      const result = verifyPkceSupport(discovery);

      // Assert
      expect(result.supported).toBe(true);
      expect(result.supportedMethods).toEqual(['S256']);
      expect(result.warning).toBeUndefined();
    });

    it('verifyPkceSupport_S256AndPlainSupported_ReturnsSupportedTrue', () => {
      // Arrange
      const discovery = createDiscoveryDoc(['plain', 'S256']);

      // Act
      const result = verifyPkceSupport(discovery);

      // Assert
      expect(result.supported).toBe(true);
      expect(result.supportedMethods).toEqual(['plain', 'S256']);
    });

    it('verifyPkceSupport_OnlyPlainSupported_ReturnsSupportedFalse', () => {
      // Arrange
      const discovery = createDiscoveryDoc(['plain']);

      // Act
      const result = verifyPkceSupport(discovery);

      // Assert
      expect(result.supported).toBe(false);
      expect(result.supportedMethods).toEqual(['plain']);
      expect(result.warning).toBeUndefined();
    });

    it('verifyPkceSupport_EmptyArray_ReturnsSupportedFalse', () => {
      // Arrange
      const discovery = createDiscoveryDoc([]);

      // Act
      const result = verifyPkceSupport(discovery);

      // Assert
      expect(result.supported).toBe(false);
      expect(result.supportedMethods).toEqual([]);
      expect(result.warning).toBeUndefined();
    });

    it('verifyPkceSupport_FieldMissing_ReturnsWarning', () => {
      // Arrange - field is undefined
      const discovery = createDiscoveryDoc(undefined);

      // Act
      const result = verifyPkceSupport(discovery);

      // Assert
      expect(result.supported).toBe(false);
      expect(result.supportedMethods).toEqual([]);
      expect(result.warning).toBeDefined();
      expect(result.warning).toContain('code_challenge_methods_supported');
    });
  });

  describe('requirePkceSupport', () => {
    const createDiscoveryDoc = (
      codeChallengeMethodsSupported?: readonly string[]
    ): OidcDiscoveryDocument => ({
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/authorize',
      token_endpoint: 'https://auth.example.com/token',
      jwks_uri: 'https://auth.example.com/jwks',
      response_types_supported: ['code'],
      code_challenge_methods_supported: codeChallengeMethodsSupported,
    });

    it('requirePkceSupport_S256Supported_ReturnsOk', () => {
      // Arrange
      const discovery = createDiscoveryDoc(['S256']);

      // Act
      const result = requirePkceSupport(discovery);

      // Assert
      expect(result.isOk()).toBe(true);
    });

    it('requirePkceSupport_OnlyPlainSupported_ReturnsError', () => {
      // Arrange
      const discovery = createDiscoveryDoc(['plain']);

      // Act
      const result = requirePkceSupport(discovery);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('pkce_error');
        expect(result.error.message).toContain('does not support PKCE S256');
        expect(result.error.message).toContain('plain');
      }
    });

    it('requirePkceSupport_EmptyMethods_ReturnsError', () => {
      // Arrange
      const discovery = createDiscoveryDoc([]);

      // Act
      const result = requirePkceSupport(discovery);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('none');
      }
    });

    it('requirePkceSupport_FieldMissing_ReturnsOkWithWarning', () => {
      // Arrange - when field is missing, we proceed (many AS support PKCE without advertising)
      const discovery = createDiscoveryDoc(undefined);

      // Act
      const result = requirePkceSupport(discovery);

      // Assert - should succeed (allow proceeding) since we can't verify
      expect(result.isOk()).toBe(true);
    });
  });
});
