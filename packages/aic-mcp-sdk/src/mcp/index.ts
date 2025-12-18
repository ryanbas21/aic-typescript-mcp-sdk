// Auth verifier (for MCP SDK's requireBearerAuth middleware)
export { createAmVerifier, createAmVerifierFromValidator } from './auth-verifier.js';

// Tool wrapper (for per-tool authentication)
export { createWithAuth } from './with-auth.js';
export type { CreateWithAuthConfig, WithAuthFn } from './with-auth.js';

// RFC 9728 Protected Resource Metadata (for MCP compliance)
export {
  createProtectedResourceMetadata,
  formatWwwAuthenticateHeader,
  parseWwwAuthenticateHeader,
} from './resource-metadata.js';
export type {
  ProtectedResourceMetadata,
  ProtectedResourceMetadataConfig,
  WwwAuthenticateChallenge,
} from './resource-metadata.js';

// Types
export type {
  McpAuthInfo,
  OAuthTokenVerifier,
  AmVerifierConfig,
  AmVerifierConfigWithSecret,
  WithAuthOptions,
  StdioTokenSource,
  TokenExtractorConfig,
} from './types.js';

// Errors
export { AuthenticationError, AuthorizationError } from './types.js';
