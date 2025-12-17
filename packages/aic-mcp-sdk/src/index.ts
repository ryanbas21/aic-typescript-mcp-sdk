/**
 * AIC MCP SDK - Authentication SDK for MCP servers
 *
 * @packageDocumentation
 */

// Public types
export type * from './types.js';

// Token validation
export { createTokenValidator } from './validation/index.js';
export { parseScopes, getMissingScopes } from './validation/index.js';
export type {
  TokenValidator,
  TokenValidatorConfig,
  JwtValidatorConfig,
  ValidationOptions,
  OidcDiscoveryDocument,
} from './validation/index.js';

// Cache utilities (for custom cache implementations)
export { createMemoryCache } from './cache/index.js';
export type { Cache, CacheEntry } from './cache/index.js';

// HTTP utilities (for custom HTTP client implementations)
export { createFetchClient } from './http/index.js';
export type {
  HttpClient,
  HttpClientOptions,
  HttpRequest,
  HttpResponse,
  HttpError,
} from './http/index.js';

// MCP integration
export {
  createAmVerifier,
  createAmVerifierFromValidator,
  createWithAuth,
  AuthenticationError,
  AuthorizationError,
} from './mcp/index.js';
export type {
  McpAuthInfo,
  OAuthTokenVerifier,
  AmVerifierConfig,
  AmVerifierConfigWithSecret,
  WithAuthOptions,
  StdioTokenSource,
  TokenExtractorConfig,
  CreateWithAuthConfig,
  WithAuthFn,
} from './mcp/index.js';
