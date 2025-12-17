/**
 * Configuration for connecting to an AIC (Authorization Identity Cloud) instance.
 */
export interface AicConfig {
  /** The base URL of the AIC instance (e.g., "https://auth.example.com") */
  readonly aicUrl: string;
  /** OAuth client ID registered in AIC */
  readonly clientId: string;
  /** OAuth client secret (for confidential clients) */
  readonly clientSecret?: string;
}

/**
 * Result of a successful token validation.
 */
export interface TokenValidationSuccess {
  readonly valid: true;
  /** The validated claims from the token */
  readonly claims: TokenClaims;
  /** Original access token */
  readonly accessToken: string;
}

/**
 * Result of a failed token validation.
 */
export interface TokenValidationFailure {
  readonly valid: false;
  /** Error code describing the failure */
  readonly error: TokenValidationError;
  /** Human-readable error message */
  readonly message: string;
  /** Information about where to authenticate */
  readonly authenticationInfo?: AuthenticationInfo;
}

/**
 * Discriminated union of token validation results.
 */
export type TokenValidationResult = TokenValidationSuccess | TokenValidationFailure;

/**
 * Standard JWT claims plus common AIC-specific claims.
 */
export interface TokenClaims {
  /** Subject (user ID) */
  readonly sub: string;
  /** Issuer */
  readonly iss: string;
  /** Audience */
  readonly aud: string | readonly string[];
  /** Expiration time (Unix timestamp) */
  readonly exp: number;
  /** Issued at time (Unix timestamp) */
  readonly iat: number;
  /** JWT ID */
  readonly jti?: string;
  /** Scopes granted to this token */
  readonly scope?: string;
  /** Client ID that requested the token */
  readonly client_id?: string;
  /** Additional custom claims */
  readonly [key: string]: unknown;
}

/**
 * Error codes for token validation failures.
 */
export type TokenValidationError =
  | 'MISSING_TOKEN'
  | 'MALFORMED_TOKEN'
  | 'EXPIRED_TOKEN'
  | 'INVALID_SIGNATURE'
  | 'INVALID_ISSUER'
  | 'INVALID_AUDIENCE'
  | 'REVOKED_TOKEN'
  | 'INSUFFICIENT_SCOPE'
  | 'VALIDATION_ERROR';

/**
 * Information provided to clients about how to authenticate.
 */
export interface AuthenticationInfo {
  /** The authorization endpoint URL */
  readonly authorizationEndpoint: string;
  /** The token endpoint URL */
  readonly tokenEndpoint: string;
  /** The issuer URL */
  readonly issuer: string;
  /** Supported scopes */
  readonly supportedScopes?: readonly string[];
}

/**
 * Configuration for token exchange operations.
 */
export interface TokenExchangeConfig {
  /** The subject token type (e.g., "urn:ietf:params:oauth:token-type:access_token") */
  readonly subjectTokenType?: string;
  /** The requested token type */
  readonly requestedTokenType?: string;
  /** Additional scopes to request */
  readonly scope?: string;
  /** Target audience for the exchanged token */
  readonly audience?: string;
  /** Additional parameters for the exchange request */
  readonly additionalParams?: Readonly<Record<string, string>>;
}

/**
 * Result of a successful token exchange.
 */
export interface TokenExchangeSuccess {
  readonly success: true;
  /** The new access token */
  readonly accessToken: string;
  /** Token type (typically "Bearer") */
  readonly tokenType: string;
  /** Expiration time in seconds */
  readonly expiresIn?: number;
  /** Scopes granted */
  readonly scope?: string;
  /** Refresh token (if provided) */
  readonly refreshToken?: string;
}

/**
 * Result of a failed token exchange.
 */
export interface TokenExchangeFailure {
  readonly success: false;
  /** OAuth error code */
  readonly error: string;
  /** Human-readable error description */
  readonly errorDescription?: string;
}

/**
 * Discriminated union of token exchange results.
 */
export type TokenExchangeResult = TokenExchangeSuccess | TokenExchangeFailure;

/**
 * Options for the AIC MCP authentication middleware.
 */
export interface AicMcpAuthOptions {
  /** AIC configuration */
  readonly config: AicConfig;
  /** Required scopes for tool access (can be per-tool or global) */
  readonly requiredScopes?: readonly string[];
  /** Whether to allow requests without tokens (defaults to false) */
  readonly allowAnonymous?: boolean;
  /** Custom token extractor function */
  readonly tokenExtractor?: TokenExtractor;
  /** Custom error handler */
  readonly onAuthError?: AuthErrorHandler;
}

/**
 * Function type for extracting tokens from incoming requests.
 */
export type TokenExtractor = (request: unknown) => string | undefined;

/**
 * Function type for handling authentication errors.
 */
export type AuthErrorHandler = (
  error: TokenValidationFailure,
  request: unknown
) => void | Promise<void>;

/**
 * Scope requirements for a specific tool.
 */
export interface ToolScopeRequirement {
  /** Tool name */
  readonly toolName: string;
  /** Required scopes for this tool */
  readonly requiredScopes: readonly string[];
}
