import type { TokenValidationResult, AuthenticationInfo } from '../types.js';

/**
 * OIDC Discovery Document as per RFC 8414.
 * Contains metadata about the OAuth 2.0 authorization server.
 */
export interface OidcDiscoveryDocument {
  /** Issuer identifier URL */
  readonly issuer: string;
  /** Authorization endpoint URL */
  readonly authorization_endpoint: string;
  /** Token endpoint URL */
  readonly token_endpoint: string;
  /** JWKS URI for public keys */
  readonly jwks_uri: string;
  /** Introspection endpoint URL (RFC 7662) */
  readonly introspection_endpoint?: string;
  /** Revocation endpoint URL (RFC 7009) */
  readonly revocation_endpoint?: string;
  /** Userinfo endpoint URL */
  readonly userinfo_endpoint?: string;
  /** Supported response types */
  readonly response_types_supported: readonly string[];
  /** Supported grant types */
  readonly grant_types_supported?: readonly string[];
  /** Supported scopes */
  readonly scopes_supported?: readonly string[];
  /** Supported token endpoint auth methods */
  readonly token_endpoint_auth_methods_supported?: readonly string[];
  /** Supported subject types */
  readonly subject_types_supported?: readonly string[];
  /** Supported ID token signing algorithms */
  readonly id_token_signing_alg_values_supported?: readonly string[];
  /** Supported claims */
  readonly claims_supported?: readonly string[];
}

/**
 * RFC 7662 Token Introspection Response.
 */
export interface IntrospectionResponse {
  /** Whether the token is currently active */
  readonly active: boolean;
  /** Scopes associated with the token */
  readonly scope?: string;
  /** Client ID that requested the token */
  readonly client_id?: string;
  /** Username of the resource owner */
  readonly username?: string;
  /** Token type (e.g., "Bearer") */
  readonly token_type?: string;
  /** Expiration timestamp */
  readonly exp?: number;
  /** Issued at timestamp */
  readonly iat?: number;
  /** Not before timestamp */
  readonly nbf?: number;
  /** Subject identifier */
  readonly sub?: string;
  /** Audience */
  readonly aud?: string | readonly string[];
  /** Issuer */
  readonly iss?: string;
  /** JWT ID */
  readonly jti?: string;
}

/**
 * Options for validating a token.
 */
export interface ValidationOptions {
  /** Required scopes that must be present */
  readonly requiredScopes?: readonly string[];
  /** Expected audience value(s) */
  readonly audience?: string | readonly string[];
  /**
   * Clock tolerance in seconds for time-based validation (default: 60).
   * The 60-second default accommodates clock skew in distributed systems.
   * For stricter security, use a lower value (e.g., 30 seconds).
   */
  readonly clockToleranceSeconds?: number;
}

/**
 * Base configuration for creating a token validator.
 * Includes clientSecret which is required for token introspection.
 */
export interface TokenValidatorConfig {
  /** Base URL of the AM instance */
  readonly amUrl: string;
  /** OAuth client ID */
  readonly clientId: string;
  /** OAuth client secret (required for token introspection) */
  readonly clientSecret: string;
  /** OAuth realm path (default: "/am/oauth2/realms/root/realms/alpha") */
  readonly realmPath?: string;
  /** Discovery document cache TTL in ms (default: 3600000 = 1 hour) */
  readonly discoveryCacheTtlMs?: number;
}

/**
 * Configuration for JWT-only token validation.
 * Does not require clientSecret since JWT validation uses JWKS public keys.
 */
export type JwtValidatorConfig = Omit<TokenValidatorConfig, 'clientSecret'>;

/**
 * Internal JWT claims after validation.
 * Based on jose JWTPayload with required fields.
 */
export interface ValidatedJwtClaims {
  readonly sub: string;
  readonly iss: string;
  readonly aud: string | string[];
  readonly exp: number;
  readonly iat: number;
  readonly jti?: string;
  readonly nbf?: number;
  readonly scope?: string | readonly string[];
  readonly client_id?: string;
  readonly [key: string]: unknown;
}

/**
 * Internal error type for validation operations.
 */
export interface ValidationError {
  readonly code:
    | 'MISSING_TOKEN'
    | 'MALFORMED_TOKEN'
    | 'EXPIRED_TOKEN'
    | 'INVALID_SIGNATURE'
    | 'INVALID_ISSUER'
    | 'INVALID_AUDIENCE'
    | 'REVOKED_TOKEN'
    | 'INSUFFICIENT_SCOPE'
    | 'DISCOVERY_ERROR'
    | 'JWKS_ERROR'
    | 'INTROSPECTION_ERROR'
    | 'NETWORK_ERROR';
  readonly message: string;
  readonly cause?: unknown;
}

/**
 * Token validator interface.
 */
export interface TokenValidator {
  /**
   * Validates a token and returns the result.
   * @param token - The access token to validate
   * @param options - Optional validation options
   */
  readonly validate: (
    token: string | undefined,
    options?: ValidationOptions
  ) => Promise<TokenValidationResult>;

  /**
   * Gets authentication info for 401 responses.
   * May return undefined if discovery hasn't been fetched yet.
   */
  readonly getAuthenticationInfo: () => Promise<AuthenticationInfo | undefined>;

  /**
   * Forces a refresh of cached discovery document and JWKS.
   */
  readonly refreshCache: () => Promise<void>;
}
