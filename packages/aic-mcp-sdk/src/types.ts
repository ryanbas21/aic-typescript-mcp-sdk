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
 * Actor claim for token delegation per RFC 8693.
 *
 * Represents an entity acting on behalf of the subject.
 * Can be nested to represent a delegation chain.
 *
 * @example
 * ```typescript
 * // Single delegation: Agent acting on behalf of user
 * const act = { sub: "https://agent1.example.com" };
 *
 * // Nested delegation: Agent2 → Agent1 → User
 * const act = {
 *   sub: "https://agent2.example.com",
 *   act: { sub: "https://agent1.example.com" }
 * };
 * ```
 */
export interface ActorClaim {
  /** Subject identifier of the actor */
  readonly sub: string;
  /** Issuer of the actor's identity (optional) */
  readonly iss?: string | undefined;
  /** Nested actor claim for delegation chains */
  readonly act?: ActorClaim | undefined;
}

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
  readonly jti?: string | undefined;
  /** Scopes granted to this token */
  readonly scope?: string | undefined;
  /** Client ID that requested the token */
  readonly client_id?: string | undefined;
  /**
   * Actor claim for delegation per RFC 8693.
   * Present when the token was obtained via token exchange
   * and represents the entity acting on behalf of the subject.
   */
  readonly act?: ActorClaim | undefined;
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
