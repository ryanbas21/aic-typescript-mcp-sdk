import { describe, it, expect } from 'vitest';
import type { TokenClaims } from '../types.js';
import {
  getDelegationChain,
  getDelegationActors,
  getDelegationDepth,
  isActorInChain,
  getImmediateActor,
  getOriginalInitiator,
  isDelegatedToken,
  getDelegationContext,
  validateDelegationChain,
  formatDelegationChain,
} from './chain.js';

/**
 * Test fixtures representing the agentic architecture flow:
 * User Login → Agent 1 → Agent 2 → MCP Server 1 → Resource Server
 */
const createBaseClaims = (): Omit<TokenClaims, 'act'> => ({
  sub: 'user@example.com',
  iss: 'https://issuer.example.com',
  aud: 'https://resource-server.example.com',
  exp: 1443904100,
  iat: 1443904000,
});

// No delegation - direct user token
const userToken: TokenClaims = {
  ...createBaseClaims(),
  aud: 'https://agent1.example.com',
};

// Single delegation: Agent 1 acting on behalf of user
const agent1Token: TokenClaims = {
  ...createBaseClaims(),
  aud: 'https://agent2.example.com',
  act: {
    sub: 'https://agent1.example.com',
  },
};

// Double delegation: Agent 2 → Agent 1 → User
const agent2Token: TokenClaims = {
  ...createBaseClaims(),
  aud: 'https://mcp-server1.example.com',
  act: {
    sub: 'https://agent2.example.com',
    act: {
      sub: 'https://agent1.example.com',
    },
  },
};

// Triple delegation: MCP Server → Agent 2 → Agent 1 → User
const mcpServerToken: TokenClaims = {
  ...createBaseClaims(),
  aud: 'https://resource-server.example.com',
  act: {
    sub: 'https://mcp-server1.example.com',
    act: {
      sub: 'https://agent2.example.com',
      act: {
        sub: 'https://agent1.example.com',
      },
    },
  },
};

// Token with issuer in act claims
const tokenWithActorIssuer: TokenClaims = {
  ...createBaseClaims(),
  act: {
    sub: 'https://agent.example.com',
    iss: 'https://auth.example.com',
  },
};

describe('Delegation chain utilities', () => {
  describe('getDelegationChain', () => {
    it('getDelegationChain_NoActClaim_ReturnsEmptyArray', () => {
      // Act
      const chain = getDelegationChain(userToken);

      // Assert
      expect(chain).toEqual([]);
    });

    it('getDelegationChain_SingleActor_ReturnsSingleElementArray', () => {
      // Act
      const chain = getDelegationChain(agent1Token);

      // Assert
      expect(chain).toEqual(['https://agent1.example.com']);
    });

    it('getDelegationChain_NestedActors_ReturnsFullChain', () => {
      // Act
      const chain = getDelegationChain(mcpServerToken);

      // Assert
      expect(chain).toEqual([
        'https://mcp-server1.example.com',
        'https://agent2.example.com',
        'https://agent1.example.com',
      ]);
    });
  });

  describe('getDelegationActors', () => {
    it('getDelegationActors_NoActClaim_ReturnsEmptyArray', () => {
      // Act
      const actors = getDelegationActors(userToken);

      // Assert
      expect(actors).toEqual([]);
    });

    it('getDelegationActors_WithIssuer_IncludesIssuer', () => {
      // Act
      const actors = getDelegationActors(tokenWithActorIssuer);

      // Assert
      expect(actors).toEqual([
        { sub: 'https://agent.example.com', iss: 'https://auth.example.com' },
      ]);
    });

    it('getDelegationActors_NestedActors_ReturnsFullActorDetails', () => {
      // Act
      const actors = getDelegationActors(agent2Token);

      // Assert
      expect(actors).toHaveLength(2);
      expect(actors[0]).toEqual({ sub: 'https://agent2.example.com' });
      expect(actors[1]).toEqual({ sub: 'https://agent1.example.com' });
    });
  });

  describe('getDelegationDepth', () => {
    it('getDelegationDepth_NoActClaim_ReturnsZero', () => {
      expect(getDelegationDepth(userToken)).toBe(0);
    });

    it('getDelegationDepth_SingleActor_ReturnsOne', () => {
      expect(getDelegationDepth(agent1Token)).toBe(1);
    });

    it('getDelegationDepth_DoubleNesting_ReturnsTwo', () => {
      expect(getDelegationDepth(agent2Token)).toBe(2);
    });

    it('getDelegationDepth_TripleNesting_ReturnsThree', () => {
      expect(getDelegationDepth(mcpServerToken)).toBe(3);
    });
  });

  describe('isActorInChain', () => {
    it('isActorInChain_ActorExists_ReturnsTrue', () => {
      expect(isActorInChain(mcpServerToken, 'https://agent1.example.com')).toBe(true);
      expect(isActorInChain(mcpServerToken, 'https://agent2.example.com')).toBe(true);
      expect(isActorInChain(mcpServerToken, 'https://mcp-server1.example.com')).toBe(true);
    });

    it('isActorInChain_ActorNotExists_ReturnsFalse', () => {
      expect(isActorInChain(mcpServerToken, 'https://unknown.example.com')).toBe(false);
    });

    it('isActorInChain_NoActClaim_ReturnsFalse', () => {
      expect(isActorInChain(userToken, 'https://agent1.example.com')).toBe(false);
    });

    it('isActorInChain_SubjectNotInActChain_ReturnsFalse', () => {
      // The subject is not in the act chain, it's the original user
      expect(isActorInChain(mcpServerToken, 'user@example.com')).toBe(false);
    });
  });

  describe('getImmediateActor', () => {
    it('getImmediateActor_NoActClaim_ReturnsUndefined', () => {
      expect(getImmediateActor(userToken)).toBeUndefined();
    });

    it('getImmediateActor_SingleActor_ReturnsThatActor', () => {
      const actor = getImmediateActor(agent1Token);
      expect(actor).toEqual({ sub: 'https://agent1.example.com' });
    });

    it('getImmediateActor_NestedActors_ReturnsFirstActor', () => {
      const actor = getImmediateActor(mcpServerToken);
      expect(actor).toEqual({ sub: 'https://mcp-server1.example.com' });
    });

    it('getImmediateActor_WithIssuer_IncludesIssuer', () => {
      const actor = getImmediateActor(tokenWithActorIssuer);
      expect(actor).toEqual({
        sub: 'https://agent.example.com',
        iss: 'https://auth.example.com',
      });
    });
  });

  describe('getOriginalInitiator', () => {
    it('getOriginalInitiator_NoActClaim_ReturnsUndefined', () => {
      expect(getOriginalInitiator(userToken)).toBeUndefined();
    });

    it('getOriginalInitiator_SingleActor_ReturnsThatActor', () => {
      const initiator = getOriginalInitiator(agent1Token);
      expect(initiator).toEqual({ sub: 'https://agent1.example.com' });
    });

    it('getOriginalInitiator_NestedActors_ReturnsDeepestActor', () => {
      const initiator = getOriginalInitiator(mcpServerToken);
      expect(initiator).toEqual({ sub: 'https://agent1.example.com' });
    });
  });

  describe('isDelegatedToken', () => {
    it('isDelegatedToken_NoActClaim_ReturnsFalse', () => {
      expect(isDelegatedToken(userToken)).toBe(false);
    });

    it('isDelegatedToken_WithActClaim_ReturnsTrue', () => {
      expect(isDelegatedToken(agent1Token)).toBe(true);
      expect(isDelegatedToken(mcpServerToken)).toBe(true);
    });
  });

  describe('getDelegationContext', () => {
    it('getDelegationContext_NoActClaim_ReturnsNonDelegatedContext', () => {
      // Act
      const context = getDelegationContext(userToken);

      // Assert
      expect(context).toEqual({
        subject: 'user@example.com',
        immediateActor: undefined,
        chain: [],
        depth: 0,
        isDelegated: false,
      });
    });

    it('getDelegationContext_WithDelegation_ReturnsFullContext', () => {
      // Act
      const context = getDelegationContext(mcpServerToken);

      // Assert
      expect(context.subject).toBe('user@example.com');
      expect(context.immediateActor).toEqual({ sub: 'https://mcp-server1.example.com' });
      expect(context.chain).toHaveLength(3);
      expect(context.depth).toBe(3);
      expect(context.isDelegated).toBe(true);
    });
  });

  describe('validateDelegationChain', () => {
    it('validateDelegationChain_NoConstraints_ReturnsValid', () => {
      const result = validateDelegationChain(mcpServerToken, {});
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('validateDelegationChain_RequireDelegation_WithDelegation_ReturnsValid', () => {
      const result = validateDelegationChain(agent1Token, { requireDelegation: true });
      expect(result.valid).toBe(true);
    });

    it('validateDelegationChain_RequireDelegation_WithoutDelegation_ReturnsInvalid', () => {
      const result = validateDelegationChain(userToken, { requireDelegation: true });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Token must be delegated (missing act claim)');
    });

    it('validateDelegationChain_MaxDepthExceeded_ReturnsInvalid', () => {
      const result = validateDelegationChain(mcpServerToken, { maxDepth: 2 });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('exceeds maximum');
    });

    it('validateDelegationChain_MaxDepthNotExceeded_ReturnsValid', () => {
      const result = validateDelegationChain(mcpServerToken, { maxDepth: 5 });
      expect(result.valid).toBe(true);
    });

    it('validateDelegationChain_RequiredActorPresent_ReturnsValid', () => {
      const result = validateDelegationChain(mcpServerToken, {
        requiredActors: ['https://agent1.example.com'],
      });
      expect(result.valid).toBe(true);
    });

    it('validateDelegationChain_RequiredActorMissing_ReturnsInvalid', () => {
      const result = validateDelegationChain(mcpServerToken, {
        requiredActors: ['https://trusted-service.example.com'],
      });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Required actor');
    });

    it('validateDelegationChain_ForbiddenActorPresent_ReturnsInvalid', () => {
      const result = validateDelegationChain(mcpServerToken, {
        forbiddenActors: ['https://agent2.example.com'],
      });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Forbidden actor');
    });

    it('validateDelegationChain_ForbiddenActorAbsent_ReturnsValid', () => {
      const result = validateDelegationChain(mcpServerToken, {
        forbiddenActors: ['https://blocked.example.com'],
      });
      expect(result.valid).toBe(true);
    });

    it('validateDelegationChain_MultipleConstraints_ChecksAll', () => {
      const result = validateDelegationChain(mcpServerToken, {
        maxDepth: 2,
        requiredActors: ['https://missing.example.com'],
        forbiddenActors: ['https://agent1.example.com'],
      });

      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(3);
    });
  });

  describe('formatDelegationChain', () => {
    it('formatDelegationChain_NoActClaim_ReturnsSubjectOnly', () => {
      const formatted = formatDelegationChain(userToken);
      expect(formatted).toBe('user@example.com');
    });

    it('formatDelegationChain_SingleActor_FormatsCorrectly', () => {
      const formatted = formatDelegationChain(agent1Token);
      expect(formatted).toBe('user@example.com ← https://agent1.example.com');
    });

    it('formatDelegationChain_NestedActors_FormatsFullChain', () => {
      const formatted = formatDelegationChain(mcpServerToken);
      expect(formatted).toBe(
        'user@example.com ← https://mcp-server1.example.com ← https://agent2.example.com ← https://agent1.example.com'
      );
    });
  });
});
