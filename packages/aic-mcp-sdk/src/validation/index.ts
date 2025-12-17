// Main factory
export { createTokenValidator } from './token-validator.js';

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
