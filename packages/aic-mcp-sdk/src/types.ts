/**
 * Configuration for connecting to an Access Management (AM) instance.
 */
export interface AmConfig {
  /** The base URL of the AM instance (e.g., "https://auth.example.com") */
  readonly amUrl: string;
  /** OAuth client ID registered in AM */
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
 * Standard JWT claims plus common AM-specific claims.
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
