// Main factory
export { createTokenValidator, introspectToken, revokeToken } from './token-validator.js';

// Scope utilities
export { parseScopes, getMissingScopes } from './scopes.js';

// Discovery utilities (RFC 8414 MCP-compliant)
export {
  // eslint-disable-next-line @typescript-eslint/no-deprecated -- Re-exporting for backwards compatibility
  buildDiscoveryUrl,
  buildDiscoveryUrls,
  // eslint-disable-next-line @typescript-eslint/no-deprecated -- Re-exporting for backwards compatibility
  fetchDiscoveryDocument,
  fetchDiscoveryDocumentWithFallback,
  createCachedDiscoveryFetcher,
  toAuthenticationInfo,
} from './discovery.js';
export type {
  DiscoveryUrlVariant,
  DiscoveryUrls,
  DiscoveryFetchResult,
  CachedDiscoveryFetcherOptions,
  CachedDiscoveryFetcher,
} from './discovery.js';

// Types
export type {
  TokenValidator,
  TokenValidatorConfig,
  JwtValidatorConfig,
  ValidationOptions,
  OidcDiscoveryDocument,
} from './types.js';
