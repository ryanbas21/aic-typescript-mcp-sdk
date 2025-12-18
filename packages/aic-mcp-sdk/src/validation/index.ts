// Main factory
export { createTokenValidator, introspectToken, revokeToken } from './token-validator.js';

// Scope utilities
export { parseScopes, getMissingScopes } from './scopes.js';

// Types
export type {
  TokenValidator,
  TokenValidatorConfig,
  JwtValidatorConfig,
  ValidationOptions,
  OidcDiscoveryDocument,
} from './types.js';
