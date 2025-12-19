/**
 * Delegation chain types for agentic architectures.
 *
 * @packageDocumentation
 */

/**
 * Represents a single actor in a delegation chain.
 */
export interface DelegationActor {
  /** Subject identifier of the actor */
  readonly sub: string;
  /** Issuer of the actor's identity (if available) */
  readonly iss?: string | undefined;
}

/**
 * Represents the full delegation context extracted from token claims.
 */
export interface DelegationContext {
  /** The original subject (end user) */
  readonly subject: string;
  /** The immediate actor (direct caller) */
  readonly immediateActor?: DelegationActor | undefined;
  /** Full delegation chain from immediate actor to original initiator */
  readonly chain: readonly DelegationActor[];
  /** Depth of the delegation chain (0 = no delegation) */
  readonly depth: number;
  /** Whether this is a delegated token */
  readonly isDelegated: boolean;
}

/**
 * Options for validating delegation chains.
 */
export interface DelegationValidationOptions {
  /** Maximum allowed delegation depth (default: unlimited) */
  readonly maxDepth?: number | undefined;
  /** Required actors that must be in the chain */
  readonly requiredActors?: readonly string[] | undefined;
  /** Forbidden actors that must NOT be in the chain */
  readonly forbiddenActors?: readonly string[] | undefined;
  /** Whether to require delegation (token must have act claim) */
  readonly requireDelegation?: boolean | undefined;
}

/**
 * Result of delegation chain validation.
 */
export interface DelegationValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}
