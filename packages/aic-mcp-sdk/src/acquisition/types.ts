/**
 * Token acquisition types for OAuth 2.0 authorization flows.
 *
 * @packageDocumentation
 */

// ============================================================================
// Client Configuration Types
// ============================================================================

/**
 * OAuth 2.0 client type per RFC 6749.
 */
export type ClientType = 'public' | 'confidential';

/**
 * Base OAuth client configuration.
 */
export interface OAuthClientConfigBase {
  /** OAuth client ID */
  readonly clientId: string;
  /** Redirect URI for authorization callback */
  readonly redirectUri: string;
  /** Default scopes to request */
  readonly scopes: readonly string[];
}

/**
 * Public client configuration (PKCE required, no client secret).
 */
export interface PublicClientConfig extends OAuthClientConfigBase {
  readonly clientType: 'public';
}

/**
 * Confidential client configuration (has client secret).
 */
export interface ConfidentialClientConfig extends OAuthClientConfigBase {
  readonly clientType: 'confidential';
  /** OAuth client secret */
  readonly clientSecret: string;
}

/**
 * Union type for OAuth client configuration.
 */
export type OAuthClientConfig = PublicClientConfig | ConfidentialClientConfig;

/**
 * Token acquisition configuration.
 */
export interface TokenAcquisitionConfig {
  /** Base URL of the AM instance (e.g., "https://openam-example.forgeblocks.com") */
  readonly amUrl: string;
  /** OAuth realm path (default: "/am/oauth2/realms/root/realms/alpha") */
  readonly realmPath?: string;
  /** OAuth client configuration */
  readonly client: OAuthClientConfig;
  /** Discovery document cache TTL in ms (default: 3600000 = 1 hour) */
  readonly discoveryCacheTtlMs?: number;
}

// ============================================================================
// PKCE Types (RFC 7636)
// ============================================================================

/**
 * PKCE challenge method.
 * MCP spec requires S256 (SHA-256).
 */
export type PkceChallengeMethod = 'S256';

/**
 * PKCE verifier/challenge pair.
 */
export interface PkceChallenge {
  /** The code verifier (random string, 43-128 chars) */
  readonly verifier: string;
  /** The code challenge (base64url-encoded SHA-256 hash of verifier) */
  readonly challenge: string;
  /** The challenge method (always 'S256' per MCP spec) */
  readonly method: PkceChallengeMethod;
}

// ============================================================================
// Authorization State Types
// ============================================================================

/**
 * Authorization state for CSRF protection and callback validation.
 */
export interface AuthorizationState {
  /** Unique state parameter for CSRF protection */
  readonly state: string;
  /** PKCE challenge pair */
  readonly pkce: PkceChallenge;
  /** Redirect URI used in authorization request */
  readonly redirectUri: string;
  /** Requested scopes */
  readonly scopes: readonly string[];
  /** Target resource (RFC 8707) */
  readonly resource?: string | undefined;
  /** Optional nonce for OpenID Connect */
  readonly nonce?: string | undefined;
  /** When this state was created (Unix timestamp ms) */
  readonly createdAt: number;
  /** When this state expires (Unix timestamp ms) */
  readonly expiresAt: number;
}

/**
 * Options for building an authorization URL.
 */
export interface AuthorizationUrlOptions {
  /** Scopes to request (overrides default client scopes) */
  readonly scopes?: readonly string[];
  /** Custom state value (auto-generated if not provided) */
  readonly state?: string;
  /** Nonce for OpenID Connect (auto-generated if not provided) */
  readonly nonce?: string;
  /** Target resource identifier (RFC 8707) */
  readonly resource?: string;
  /** Prompt behavior */
  readonly prompt?: 'none' | 'login' | 'consent' | 'select_account';
  /** Hint for login identifier */
  readonly loginHint?: string;
  /** ACR values for authentication context */
  readonly acrValues?: string;
  /** State TTL in milliseconds (default: 600000 = 10 minutes) */
  readonly stateTtlMs?: number;
}

/**
 * PKCE support verification result.
 */
export interface PkceSupportInfo {
  /** Whether PKCE S256 is verified as supported */
  readonly verified: boolean;
  /** The supported methods from the discovery document */
  readonly supportedMethods: readonly string[];
  /** Warning message if PKCE support could not be verified */
  readonly warning?: string | undefined;
}

/**
 * Result of building an authorization URL.
 */
export interface AuthorizationUrlResult {
  /** The authorization URL to redirect the user to */
  readonly url: string;
  /** The state value to validate in callback */
  readonly state: string;
  /** The full authorization state (stored for callback validation) */
  readonly authorizationState: AuthorizationState;
  /** PKCE support verification result per MCP spec */
  readonly pkceSupport: PkceSupportInfo;
}

// ============================================================================
// Token Types
// ============================================================================

/**
 * OAuth token type.
 */
export type TokenType = 'Bearer' | 'DPoP';

/**
 * Token set containing access token and related data.
 */
export interface TokenSet {
  /** The access token */
  readonly accessToken: string;
  /** Token type (typically "Bearer") */
  readonly tokenType: TokenType;
  /** When the access token expires (Unix timestamp ms) */
  readonly expiresAt: number;
  /** Refresh token for obtaining new access tokens */
  readonly refreshToken?: string;
  /** Scopes granted to this token */
  readonly scopes: readonly string[];
  /** ID token (if openid scope was requested) */
  readonly idToken?: string;
  /** Target resource this token was issued for */
  readonly resource?: string;
}

/**
 * Raw OAuth token response from token endpoint.
 */
export interface TokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in: number;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly id_token?: string;
}

// ============================================================================
// Token Exchange Types (RFC 8693)
// ============================================================================

/**
 * Token type identifiers per RFC 8693.
 */
export type SubjectTokenType =
  | 'urn:ietf:params:oauth:token-type:access_token'
  | 'urn:ietf:params:oauth:token-type:refresh_token'
  | 'urn:ietf:params:oauth:token-type:id_token'
  | 'urn:ietf:params:oauth:token-type:jwt';

/**
 * Token exchange request parameters per RFC 8693.
 */
export interface TokenExchangeRequest {
  /** The subject token to exchange */
  readonly subjectToken: string;
  /** Type of the subject token */
  readonly subjectTokenType: SubjectTokenType;
  /** Requested token type (defaults to access_token) */
  readonly requestedTokenType?: SubjectTokenType;
  /** Target audience for the exchanged token */
  readonly audience?: string;
  /** Requested scopes for the exchanged token */
  readonly scope?: string;
  /** Target resource for the exchanged token */
  readonly resource?: string;
  /** Optional actor token for delegation scenarios */
  readonly actorToken?: string;
  /** Type of the actor token */
  readonly actorTokenType?: SubjectTokenType;
}

/**
 * Token exchange response.
 */
export interface TokenExchangeResponse extends TokenSet {
  /** The type of token that was issued */
  readonly issuedTokenType: SubjectTokenType;
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Token acquisition error codes.
 * Includes standard OAuth 2.0 error codes plus SDK-specific codes.
 */
export type TokenAcquisitionErrorCode =
  // OAuth 2.0 standard errors (RFC 6749)
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'access_denied'
  | 'server_error'
  | 'temporarily_unavailable'
  // Token-specific errors
  | 'invalid_token'
  | 'expired_token'
  // SDK-specific errors
  | 'network_error'
  | 'discovery_error'
  | 'pkce_error'
  | 'state_mismatch'
  | 'state_expired'
  | 'state_not_found'
  | 'unsupported_token_type';

/**
 * Token acquisition error.
 */
export interface TokenAcquisitionError {
  /** Error code */
  readonly code: TokenAcquisitionErrorCode;
  /** Human-readable error message */
  readonly message: string;
  /** OAuth error_description from server */
  readonly errorDescription?: string | undefined;
  /** OAuth error_uri from server */
  readonly errorUri?: string | undefined;
  /** Underlying cause */
  readonly cause?: unknown;
}

// ============================================================================
// Result Types
// ============================================================================

/**
 * Successful token acquisition result.
 */
export interface TokenAcquisitionSuccess {
  readonly success: true;
  readonly tokens: TokenSet;
}

/**
 * Failed token acquisition result.
 */
export interface TokenAcquisitionFailure {
  readonly success: false;
  readonly error: TokenAcquisitionError;
}

/**
 * Token acquisition result (discriminated union).
 */
export type TokenAcquisitionResult = TokenAcquisitionSuccess | TokenAcquisitionFailure;

/**
 * Successful token exchange result.
 */
export interface TokenExchangeSuccess {
  readonly success: true;
  readonly tokens: TokenExchangeResponse;
}

/**
 * Failed token exchange result.
 */
export interface TokenExchangeFailure {
  readonly success: false;
  readonly error: TokenAcquisitionError;
}

/**
 * Token exchange result (discriminated union).
 */
export type TokenExchangeResult = TokenExchangeSuccess | TokenExchangeFailure;

// ============================================================================
// Token Manager Types
// ============================================================================

/**
 * Options for client credentials token acquisition.
 */
export interface ClientCredentialsOptions {
  /** Scopes to request (overrides default client scopes) */
  readonly scopes?: readonly string[];
  /** Target resource (RFC 8707) */
  readonly resource?: string;
}

/**
 * Options for refreshing tokens.
 */
export interface RefreshOptions {
  /** Scopes to request (can be subset of original scopes) */
  readonly scopes?: readonly string[];
}

/**
 * Token manager configuration.
 */
export interface TokenManagerConfig extends TokenAcquisitionConfig {
  /**
   * Buffer time in seconds before expiry to consider token as expiring.
   * Default: 60 (refresh token 60s before it expires)
   */
  readonly refreshBufferSeconds?: number;
}

/**
 * Token manager interface for orchestrating token acquisition flows.
 */
export interface TokenManager {
  /**
   * Initiates the authorization code flow.
   * Returns the URL to redirect the user to for authentication.
   *
   * @param options - Authorization options
   * @returns Result with authorization URL and state
   */
  readonly startAuthorization: (
    options?: AuthorizationUrlOptions
  ) => Promise<TokenAcquisitionResult | AuthorizationUrlResult>;

  /**
   * Handles the OAuth callback and exchanges the authorization code for tokens.
   *
   * @param code - The authorization code from the callback
   * @param state - The state parameter from the callback
   * @returns Result with tokens or error
   */
  readonly handleCallback: (code: string, state: string) => Promise<TokenAcquisitionResult>;

  /**
   * Gets a valid access token, refreshing if necessary.
   * Returns error if no tokens are available and user hasn't authenticated.
   *
   * @returns Result with access token string or error
   */
  readonly getAccessToken: () => Promise<
    { readonly success: true; readonly accessToken: string } | TokenAcquisitionFailure
  >;

  /**
   * Gets the current token set (if available).
   *
   * @returns The current token set or undefined
   */
  readonly getTokenSet: () => Promise<TokenSet | undefined>;

  /**
   * Gets a service token using client credentials flow.
   * Only available for confidential clients.
   *
   * @param options - Client credentials options
   * @returns Result with tokens or error
   */
  readonly getServiceToken: (options?: ClientCredentialsOptions) => Promise<TokenAcquisitionResult>;

  /**
   * Exchanges a token for a new token (RFC 8693).
   * Used for identity delegation when calling downstream services.
   * Only available for confidential clients.
   *
   * @param request - Token exchange request
   * @returns Result with exchanged tokens or error
   */
  readonly exchangeToken: (request: TokenExchangeRequest) => Promise<TokenExchangeResult>;

  /**
   * Clears all stored tokens.
   */
  readonly clearTokens: () => Promise<void>;

  /**
   * Revokes the current access token.
   *
   * @returns Result indicating success or error
   */
  readonly revokeToken: () => Promise<
    { readonly success: true; readonly revoked: true } | TokenAcquisitionFailure
  >;
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard to check if client config is confidential.
 */
export const isConfidentialClient = (
  config: OAuthClientConfig
): config is ConfidentialClientConfig => {
  return config.clientType === 'confidential';
};

/**
 * Type guard to check if client config is public.
 */
export const isPublicClient = (config: OAuthClientConfig): config is PublicClientConfig => {
  return config.clientType === 'public';
};

/**
 * Type guard for successful token acquisition.
 */
export const isTokenAcquisitionSuccess = (
  result: TokenAcquisitionResult
): result is TokenAcquisitionSuccess => {
  return result.success;
};

/**
 * Type guard for failed token acquisition.
 */
export const isTokenAcquisitionFailure = (
  result: TokenAcquisitionResult
): result is TokenAcquisitionFailure => {
  return !result.success;
};
