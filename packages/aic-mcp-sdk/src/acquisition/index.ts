/**
 * Token acquisition module for OAuth 2.0 authorization flows.
 *
 * Provides APIs for:
 * - Authorization code flow with PKCE (user authentication)
 * - Token refresh (on-demand)
 * - Client credentials (service tokens)
 * - Token exchange per RFC 8693 (identity delegation)
 *
 * @packageDocumentation
 */

// Types
export type {
  // Client configuration
  ClientType,
  OAuthClientConfigBase,
  PublicClientConfig,
  ConfidentialClientConfig,
  OAuthClientConfig,
  TokenAcquisitionConfig,
  // PKCE
  PkceChallengeMethod,
  PkceChallenge,
  PkceSupportInfo,
  // Authorization state
  AuthorizationState,
  AuthorizationUrlOptions,
  AuthorizationUrlResult,
  // Tokens
  TokenType,
  TokenSet,
  TokenResponse,
  // Token exchange (RFC 8693)
  SubjectTokenType,
  TokenExchangeRequest,
  TokenExchangeResponse,
  // Errors
  TokenAcquisitionErrorCode,
  TokenAcquisitionError,
  // Results
  TokenAcquisitionSuccess,
  TokenAcquisitionFailure,
  TokenAcquisitionResult,
  TokenExchangeSuccess,
  TokenExchangeFailure,
  TokenExchangeResult,
  // Token manager
  ClientCredentialsOptions,
  RefreshOptions,
  TokenManagerConfig,
  TokenManager,
} from './types.js';

// Type guards
export {
  isConfidentialClient,
  isPublicClient,
  isTokenAcquisitionSuccess,
  isTokenAcquisitionFailure,
} from './types.js';

// PKCE utilities
export {
  generatePkceVerifier,
  createPkceChallenge,
  validatePkceChallenge,
  generatePkceChallengePair,
  // PKCE support verification (MCP spec compliance)
  verifyPkceSupport,
  requirePkceSupport,
} from './pkce.js';
export type { PkceSupportResult } from './pkce.js';

// State management
export {
  generateState,
  generateNonce,
  createAuthorizationState,
  retrieveAuthorizationState,
  consumeAuthorizationState,
  validateCallbackState,
} from './state.js';

// Authorization URL builder
export { createAuthorizationUrlBuilder } from './authorization-url.js';
export type {
  AuthorizationUrlBuilder,
  AuthorizationUrlBuilderResult,
} from './authorization-url.js';

// Token client
export { createTokenClient } from './token-client.js';
export type {
  TokenClient,
  CodeExchangeOptions,
  RefreshOptions as TokenRefreshOptions,
} from './token-client.js';

// Client credentials
export { createClientCredentialsAcquirer } from './client-credentials.js';
export type { ClientCredentialsConfig, ClientCredentialsAcquirer } from './client-credentials.js';

// Token exchange (RFC 8693)
export { createTokenExchanger } from './token-exchange.js';
export type { TokenExchangeConfig, TokenExchanger } from './token-exchange.js';

// Token manager (main orchestrator)
export { createTokenManager } from './token-manager.js';
