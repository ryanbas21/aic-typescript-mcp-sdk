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
 * Error thrown when authentication fails (HTTP 401).
 * This indicates the request lacks valid authentication credentials.
 *
 * Per MCP spec, 401 responses should include WWW-Authenticate header
 * pointing to the protected resource metadata endpoint.
 *
 * @example
 * ```typescript
 * try {
 *   await validateToken(token);
 * } catch (error) {
 *   if (error instanceof AuthenticationError) {
 *     const wwwAuth = formatWwwAuthenticateHeader({
 *       resourceMetadataUrl: 'https://server.com/.well-known/oauth-protected-resource',
 *       error: 'invalid_token',
 *       errorDescription: error.message,
 *     });
 *     res.status(401).header('WWW-Authenticate', wwwAuth).send();
 *   }
 * }
 * ```
 */
export class AuthenticationError extends Error {
  /**
   * Error code describing the authentication failure.
   * One of: MISSING_TOKEN, MALFORMED_TOKEN, EXPIRED_TOKEN, INVALID_SIGNATURE,
   * INVALID_ISSUER, INVALID_AUDIENCE, REVOKED_TOKEN, VALIDATION_ERROR
   */
  readonly code: string;

  /**
   * Information about the authorization server for 401 responses.
   * Can be used to help clients discover where to authenticate.
   */
  readonly authenticationInfo: AuthenticationInfo | undefined;

  /**
   * HTTP status code for this error (always 401).
   */
  readonly httpStatusCode = 401 as const;

  constructor(result: TokenValidationResult & { valid: false }) {
    super(result.message);
    this.name = 'AuthenticationError';
    this.code = result.error;
    this.authenticationInfo = result.authenticationInfo;
  }
}

/**
 * Error thrown when authorization fails due to insufficient scopes (HTTP 403).
 * This indicates the token is valid but lacks required permissions.
 *
 * Per MCP spec, 403 responses should be used for scope failures,
 * not 401 (which is for authentication failures).
 *
 * @example
 * ```typescript
 * try {
 *   checkScopes(requiredScopes, tokenScopes);
 * } catch (error) {
 *   if (error instanceof AuthorizationError) {
 *     res.status(403).json({
 *       error: 'insufficient_scope',
 *       required_scopes: error.requiredScopes,
 *       present_scopes: error.presentScopes,
 *     });
 *   }
 * }
 * ```
 */
export class AuthorizationError extends Error {
  /**
   * Scopes that were required for this operation.
   */
  readonly requiredScopes: readonly string[];

  /**
   * Scopes that were present in the token.
   */
  readonly presentScopes: readonly string[];

  /**
   * Scopes that are missing (required but not present).
   */
  readonly missingScopes: readonly string[];

  /**
   * HTTP status code for this error (always 403).
   */
  readonly httpStatusCode = 403 as const;

  constructor(requiredScopes: readonly string[], presentScopes: readonly string[]) {
    const missing = requiredScopes.filter((s) => !presentScopes.includes(s));
    super(`Insufficient scopes. Missing: ${missing.join(', ')}`);
    this.name = 'AuthorizationError';
    this.requiredScopes = requiredScopes;
    this.presentScopes = presentScopes;
    this.missingScopes = missing;
  }
}
