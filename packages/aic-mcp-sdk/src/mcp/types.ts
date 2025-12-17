import type { TokenValidationResult, AuthenticationInfo } from '../types.js';

/**
 * MCP SDK's AuthInfo interface.
 * We define our own to avoid requiring @modelcontextprotocol/sdk as a hard dependency.
 */
export interface McpAuthInfo {
  /** The access token */
  readonly token: string;
  /** Associated client ID */
  readonly clientId: string;
  /** Token scopes */
  readonly scopes: readonly string[];
  /** Expiration timestamp (seconds since epoch) */
  readonly expiresAt?: number;
  /** Custom data storage */
  readonly extra?: Readonly<Record<string, unknown>>;
}

/**
 * MCP SDK's OAuthTokenVerifier interface.
 */
export interface OAuthTokenVerifier {
  /**
   * Verifies an access token and returns auth info.
   * @param token - The access token to verify
   * @throws Error if token is invalid
   */
  readonly verifyAccessToken: (token: string) => Promise<McpAuthInfo>;
}

/**
 * Configuration for creating an AM token verifier for JWT validation.
 * Does not require clientSecret since JWT validation uses JWKS public keys.
 */
export interface AmVerifierConfig {
  /** Base URL of the AM instance */
  readonly amUrl: string;
  /** OAuth client ID */
  readonly clientId: string;
  /** OAuth realm path (default: "/am/oauth2/realms/root/realms/alpha") */
  readonly realmPath?: string;
}

/**
 * Configuration for creating an AM token verifier with introspection support.
 * Requires clientSecret for RFC 7662 token introspection.
 */
export interface AmVerifierConfigWithSecret extends AmVerifierConfig {
  /** OAuth client secret (required for token introspection) */
  readonly clientSecret: string;
}

/**
 * Options for the withAuth tool wrapper.
 */
export interface WithAuthOptions {
  /** Required scopes for this tool */
  readonly requiredScopes?: readonly string[];
}

/**
 * Token source for stdio transport.
 */
export type StdioTokenSource = 'env' | 'meta' | 'both' | (() => string | undefined);

/**
 * Configuration for token extraction.
 */
export interface TokenExtractorConfig {
  /**
   * Environment variable name for token (default: "AIC_ACCESS_TOKEN")
   */
  readonly envVar?: string;
  /**
   * Meta field name for per-request token (default: "accessToken")
   */
  readonly metaField?: string;
  /**
   * Token source priority for stdio (default: "both")
   * - "env": Only use environment variable
   * - "meta": Only use _meta field from request
   * - "both": Try _meta first, fall back to env
   * - function: Custom token extractor
   */
  readonly stdioTokenSource?: StdioTokenSource;
}

/**
 * Error thrown when authentication fails.
 */
export class AuthenticationError extends Error {
  readonly code: string;
  readonly authenticationInfo: AuthenticationInfo | undefined;

  constructor(result: TokenValidationResult & { valid: false }) {
    super(result.message);
    this.name = 'AuthenticationError';
    this.code = result.error;
    this.authenticationInfo = result.authenticationInfo;
  }
}

/**
 * Error thrown when authorization fails (e.g., insufficient scopes).
 */
export class AuthorizationError extends Error {
  readonly requiredScopes: readonly string[];
  readonly presentScopes: readonly string[];

  constructor(requiredScopes: readonly string[], presentScopes: readonly string[]) {
    const missing = requiredScopes.filter((s) => !presentScopes.includes(s));
    super(`Insufficient scopes. Missing: ${missing.join(', ')}`);
    this.name = 'AuthorizationError';
    this.requiredScopes = requiredScopes;
    this.presentScopes = presentScopes;
  }
}
