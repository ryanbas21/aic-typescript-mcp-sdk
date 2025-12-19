/**
 * Delegation chain utilities for working with RFC 8693 actor claims.
 *
 * These utilities help parse, traverse, and validate delegation chains
 * in agentic architectures where tokens flow through multiple services.
 *
 * @packageDocumentation
 */

import type { ActorClaim, TokenClaims } from '../types.js';
import type {
  DelegationActor,
  DelegationContext,
  DelegationValidationOptions,
  DelegationValidationResult,
} from './types.js';

/**
 * Extracts the delegation chain from token claims.
 *
 * Returns an array of actors from the immediate actor (index 0)
 * to the original initiator (last index).
 *
 * @param claims - Token claims containing optional `act` claim
 * @returns Array of actor subjects in delegation order
 *
 * @example
 * ```typescript
 * // Token with nested delegation: MCP Server → Agent2 → Agent1
 * const claims = {
 *   sub: "user@example.com",
 *   act: {
 *     sub: "https://mcp-server.example.com",
 *     act: {
 *       sub: "https://agent2.example.com",
 *       act: { sub: "https://agent1.example.com" }
 *     }
 *   }
 * };
 *
 * getDelegationChain(claims);
 * // => ["https://mcp-server.example.com", "https://agent2.example.com", "https://agent1.example.com"]
 * ```
 */
export const getDelegationChain = (claims: TokenClaims): readonly string[] => {
  const chain: string[] = [];
  let current: ActorClaim | undefined = claims.act;

  while (current !== undefined) {
    chain.push(current.sub);
    current = current.act;
  }

  return chain;
};

/**
 * Extracts detailed delegation actors from token claims.
 *
 * Similar to `getDelegationChain` but includes full actor information
 * including issuer when available.
 *
 * @param claims - Token claims containing optional `act` claim
 * @returns Array of delegation actors with full details
 *
 * @example
 * ```typescript
 * const actors = getDelegationActors(claims);
 * // => [{ sub: "https://agent.example.com", iss: "https://auth.example.com" }]
 * ```
 */
export const getDelegationActors = (claims: TokenClaims): readonly DelegationActor[] => {
  const actors: DelegationActor[] = [];
  let current: ActorClaim | undefined = claims.act;

  while (current !== undefined) {
    const actor: DelegationActor = {
      sub: current.sub,
      ...(current.iss !== undefined ? { iss: current.iss } : {}),
    };
    actors.push(actor);
    current = current.act;
  }

  return actors;
};

/**
 * Gets the depth of the delegation chain.
 *
 * @param claims - Token claims containing optional `act` claim
 * @returns Number of actors in the delegation chain (0 = no delegation)
 *
 * @example
 * ```typescript
 * // No delegation
 * getDelegationDepth({ sub: "user", ... }); // => 0
 *
 * // Single delegation
 * getDelegationDepth({ sub: "user", act: { sub: "agent" }, ... }); // => 1
 *
 * // Nested delegation
 * getDelegationDepth({
 *   sub: "user",
 *   act: { sub: "agent2", act: { sub: "agent1" } },
 *   ...
 * }); // => 2
 * ```
 */
export const getDelegationDepth = (claims: TokenClaims): number => {
  return getDelegationChain(claims).length;
};

/**
 * Checks if a specific actor is in the delegation chain.
 *
 * @param claims - Token claims containing optional `act` claim
 * @param actor - Actor subject to search for
 * @returns true if the actor is in the chain
 *
 * @example
 * ```typescript
 * const claims = {
 *   sub: "user@example.com",
 *   act: {
 *     sub: "https://agent2.example.com",
 *     act: { sub: "https://agent1.example.com" }
 *   }
 * };
 *
 * isActorInChain(claims, "https://agent1.example.com"); // => true
 * isActorInChain(claims, "https://unknown.example.com"); // => false
 * ```
 */
export const isActorInChain = (claims: TokenClaims, actor: string): boolean => {
  return getDelegationChain(claims).includes(actor);
};

/**
 * Gets the immediate actor (direct caller) from the delegation chain.
 *
 * @param claims - Token claims containing optional `act` claim
 * @returns The immediate actor or undefined if no delegation
 *
 * @example
 * ```typescript
 * const claims = {
 *   sub: "user@example.com",
 *   act: {
 *     sub: "https://mcp-server.example.com",
 *     act: { sub: "https://agent.example.com" }
 *   }
 * };
 *
 * getImmediateActor(claims);
 * // => { sub: "https://mcp-server.example.com" }
 * ```
 */
export const getImmediateActor = (claims: TokenClaims): DelegationActor | undefined => {
  if (claims.act === undefined) {
    return undefined;
  }

  return {
    sub: claims.act.sub,
    ...(claims.act.iss !== undefined ? { iss: claims.act.iss } : {}),
  };
};

/**
 * Gets the original initiator (first actor in the chain).
 *
 * In a delegation chain User → Agent1 → Agent2 → MCP Server,
 * this returns Agent1 (the first service that initiated the delegation).
 *
 * @param claims - Token claims containing optional `act` claim
 * @returns The original initiating actor or undefined if no delegation
 *
 * @example
 * ```typescript
 * const claims = {
 *   sub: "user@example.com",
 *   act: {
 *     sub: "https://mcp-server.example.com",
 *     act: { sub: "https://agent.example.com" }
 *   }
 * };
 *
 * getOriginalInitiator(claims);
 * // => { sub: "https://agent.example.com" }
 * ```
 */
export const getOriginalInitiator = (claims: TokenClaims): DelegationActor | undefined => {
  const actors = getDelegationActors(claims);
  return actors.length > 0 ? actors[actors.length - 1] : undefined;
};

/**
 * Checks if the token is a delegated token (has act claim).
 *
 * @param claims - Token claims
 * @returns true if the token has delegation
 */
export const isDelegatedToken = (claims: TokenClaims): boolean => {
  return claims.act !== undefined;
};

/**
 * Extracts the full delegation context from token claims.
 *
 * Provides a comprehensive view of the delegation including subject,
 * immediate actor, full chain, and metadata.
 *
 * @param claims - Token claims containing optional `act` claim
 * @returns Full delegation context
 *
 * @example
 * ```typescript
 * const context = getDelegationContext(claims);
 *
 * console.log(context.subject);        // "user@example.com"
 * console.log(context.immediateActor); // { sub: "https://mcp-server.example.com" }
 * console.log(context.chain);          // [{ sub: "https://mcp-server.example.com" }, ...]
 * console.log(context.depth);          // 2
 * console.log(context.isDelegated);    // true
 * ```
 */
export const getDelegationContext = (claims: TokenClaims): DelegationContext => {
  const chain = getDelegationActors(claims);

  return {
    subject: claims.sub,
    immediateActor: chain.length > 0 ? chain[0] : undefined,
    chain,
    depth: chain.length,
    isDelegated: chain.length > 0,
  };
};

/**
 * Validates a delegation chain against specified constraints.
 *
 * @param claims - Token claims to validate
 * @param options - Validation options
 * @returns Validation result with any errors
 *
 * @example
 * ```typescript
 * // Validate max depth and required actors
 * const result = validateDelegationChain(claims, {
 *   maxDepth: 3,
 *   requiredActors: ["https://trusted-agent.example.com"],
 *   forbiddenActors: ["https://blocked-service.example.com"],
 * });
 *
 * if (!result.valid) {
 *   console.error("Delegation validation failed:", result.errors);
 * }
 * ```
 */
export const validateDelegationChain = (
  claims: TokenClaims,
  options: DelegationValidationOptions
): DelegationValidationResult => {
  const errors: string[] = [];
  const chain = getDelegationChain(claims);
  const depth = chain.length;

  // Check if delegation is required
  if (options.requireDelegation === true && depth === 0) {
    errors.push('Token must be delegated (missing act claim)');
  }

  // Check max depth
  if (options.maxDepth !== undefined && depth > options.maxDepth) {
    errors.push(
      `Delegation chain depth ${String(depth)} exceeds maximum ${String(options.maxDepth)}`
    );
  }

  // Check required actors
  if (options.requiredActors !== undefined) {
    for (const requiredActor of options.requiredActors) {
      if (!chain.includes(requiredActor)) {
        errors.push(`Required actor "${requiredActor}" not found in delegation chain`);
      }
    }
  }

  // Check forbidden actors
  if (options.forbiddenActors !== undefined) {
    for (const forbiddenActor of options.forbiddenActors) {
      if (chain.includes(forbiddenActor)) {
        errors.push(`Forbidden actor "${forbiddenActor}" found in delegation chain`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
};

/**
 * Formats a delegation chain as a human-readable string.
 *
 * @param claims - Token claims
 * @returns Formatted string showing delegation flow
 *
 * @example
 * ```typescript
 * formatDelegationChain(claims);
 * // => "user@example.com ← agent1.example.com ← agent2.example.com ← mcp-server.example.com"
 * ```
 */
export const formatDelegationChain = (claims: TokenClaims): string => {
  const chain = getDelegationChain(claims);

  if (chain.length === 0) {
    return claims.sub;
  }

  // Show: subject ← actor1 ← actor2 ← ... (arrows show "on behalf of" direction)
  return [claims.sub, ...chain].join(' ← ');
};
