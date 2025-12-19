/**
 * AIC MCP SDK - Authentication SDK for MCP servers
 *
 * @packageDocumentation
 */

// Public types
export type * from './types.js';

// ============================================================================
// CORE: Token Validation
// ============================================================================

export { createTokenValidator } from './validation/index.js';
export type {
  TokenValidator,
  TokenValidatorConfig,
  JwtValidatorConfig,
  ValidationOptions,
  OidcDiscoveryDocument,
} from './validation/index.js';

// ============================================================================
// CORE: MCP Integration
// ============================================================================

export {
  createWithAuth,
  AuthenticationError,
  AuthorizationError,
  // RFC 9728 Protected Resource Metadata (for MCP compliance)
  createProtectedResourceMetadata,
  formatWwwAuthenticateHeader,
} from './mcp/index.js';
export type {
  McpAuthInfo,
  OAuthTokenVerifier,
  WithAuthOptions,
  CreateWithAuthConfig,
  WithAuthFn,
  // RFC 9728 types
  ProtectedResourceMetadata,
  ProtectedResourceMetadataConfig,
  WwwAuthenticateChallenge,
} from './mcp/index.js';

// ============================================================================
// CORE: Token Acquisition (High-Level API)
// ============================================================================

export {
  // Token manager (main API)
  createTokenManager,
  // Client credentials acquirer (for service tokens / actor tokens)
  createClientCredentialsAcquirer,
  // Type guards
  isConfidentialClient,
  isPublicClient,
  isTokenAcquisitionSuccess,
  isTokenAcquisitionFailure,
} from './acquisition/index.js';
export type {
  // Client configuration
  ClientType,
  OAuthClientConfigBase,
  PublicClientConfig,
  ConfidentialClientConfig,
  OAuthClientConfig,
  TokenAcquisitionConfig,
  // Authorization state
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
  // Client credentials acquirer
  ClientCredentialsConfig,
  ClientCredentialsAcquirer,
} from './acquisition/index.js';

// ============================================================================
// CORE: Storage (for token persistence)
// ============================================================================

export { createMemoryStorage } from './storage/index.js';
export type { SecureStorage, StorageEntry } from './storage/index.js';

// ============================================================================
// ADVANCED: Custom Cache/HTTP Implementations
// ============================================================================

export { createMemoryCache } from './cache/index.js';
export type { Cache, CacheEntry } from './cache/index.js';

export { createFetchClient } from './http/index.js';
export type {
  HttpClient,
  HttpClientOptions,
  HttpRequest,
  HttpResponse,
  HttpError,
} from './http/index.js';

// ============================================================================
// ADVANCED: Discovery (for custom caching strategies)
// ============================================================================

export { createCachedDiscoveryFetcher } from './validation/index.js';
export type { CachedDiscoveryFetcherOptions, CachedDiscoveryFetcher } from './validation/index.js';

// ============================================================================
// ADVANCED: Delegation Chain Utilities (RFC 8693 actor claims)
// ============================================================================

export {
  getDelegationContext,
  isDelegatedToken,
  validateDelegationChain,
} from './delegation/index.js';
export type {
  DelegationActor,
  DelegationContext,
  DelegationValidationOptions,
  DelegationValidationResult,
} from './delegation/index.js';

// ============================================================================
// ADVANCED: Client Metadata Documents (MCP spec - dynamic registration)
// ============================================================================

export {
  buildClientMetadataDocument,
  fetchClientMetadataDocument,
} from './client-metadata/index.js';
export type {
  GrantType,
  ResponseType,
  TokenEndpointAuthMethod,
  ClientMetadataDocument,
  ClientMetadataErrorCode,
  ClientMetadataError,
  ClientMetadataOptions,
  ClientMetadataFetchResult,
  FetchClientMetadataOptions,
} from './client-metadata/index.js';

// ============================================================================
// ADVANCED: PKCE Support Verification (MCP spec compliance)
// ============================================================================

export { verifyPkceSupport, requirePkceSupport } from './acquisition/index.js';
export type { PkceSupportInfo, PkceSupportResult } from './acquisition/index.js';
