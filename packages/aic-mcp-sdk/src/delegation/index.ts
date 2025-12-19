/**
 * Delegation module for working with RFC 8693 token exchange
 * and agentic delegation chains.
 *
 * @packageDocumentation
 */

// Types
export type {
  DelegationActor,
  DelegationContext,
  DelegationValidationOptions,
  DelegationValidationResult,
} from './types.js';

// Chain utilities
export {
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
