/**
 * Shared test fixtures and constants.
 * Provides meaningful, reusable test data following DRY principles.
 */

import type { OidcDiscoveryDocument } from '../validation/types.js';
import type { AuthenticationInfo } from '../types.js';

// ============================================================================
// Time Constants
// ============================================================================

/** One hour in milliseconds */
export const ONE_HOUR_MS = 60 * 60 * 1000;

/** One minute in seconds */
export const ONE_MINUTE_SECONDS = 60;

/** Current timestamp for tests (fixed for determinism) */
export const FIXED_TIMESTAMP_SECONDS = Math.floor(Date.now() / 1000);

// ============================================================================
// URL Constants
// ============================================================================

export const TEST_AM_URL = 'https://auth.example.com';
export const TEST_REALM_PATH = '/am/oauth2/realms/root/realms/alpha';
export const TEST_ISSUER = `${TEST_AM_URL}${TEST_REALM_PATH}`;
export const TEST_JWKS_URI = `${TEST_ISSUER}/connect/jwks`;
export const TEST_AUTHORIZATION_ENDPOINT = `${TEST_ISSUER}/authorize`;
export const TEST_TOKEN_ENDPOINT = `${TEST_ISSUER}/access_token`;
export const TEST_INTROSPECTION_ENDPOINT = `${TEST_ISSUER}/introspect`;

// ============================================================================
// Client Configuration
// ============================================================================

export const TEST_CLIENT_ID = 'test-client-id';
export const TEST_CLIENT_SECRET = 'test-client-secret';

// ============================================================================
// Token Claims
// ============================================================================

export const TEST_SUBJECT = 'user-123';
export const TEST_AUDIENCE = 'api.example.com';
export const TEST_JWT_ID = 'jwt-abc-123';

// ============================================================================
// Scopes
// ============================================================================

export const SCOPE_READ = 'read';
export const SCOPE_WRITE = 'write';
export const SCOPE_DELETE = 'delete';
export const SCOPE_ADMIN = 'admin';

/** Common read/write scope string */
export const SCOPES_READ_WRITE = `${SCOPE_READ} ${SCOPE_WRITE}`;

/** All available scopes */
export const ALL_SCOPES = [SCOPE_READ, SCOPE_WRITE, SCOPE_DELETE, SCOPE_ADMIN] as const;

// ============================================================================
// JWT Test Data
// ============================================================================

/**
 * A valid JWT header (base64url encoded).
 * Decodes to: {"alg":"RS256","typ":"JWT"}
 */
export const VALID_JWT_HEADER = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9';

/**
 * A sample JWT payload (base64url encoded).
 * Contains standard claims for testing.
 */
export const SAMPLE_JWT_PAYLOAD =
  'eyJzdWIiOiJ1c2VyLTEyMyIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFwaS5leGFtcGxlLmNvbSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNzAwMDAwMDAwfQ';

/**
 * A sample JWT signature (base64url encoded, not cryptographically valid).
 */
export const SAMPLE_JWT_SIGNATURE = 'dGVzdC1zaWduYXR1cmU';

/**
 * A syntactically valid JWT for format checking (not cryptographically valid).
 */
export const VALID_FORMAT_JWT = `${VALID_JWT_HEADER}.${SAMPLE_JWT_PAYLOAD}.${SAMPLE_JWT_SIGNATURE}`;

// ============================================================================
// Discovery Document Fixtures
// ============================================================================

/**
 * Creates a valid OIDC discovery document for testing.
 */
export const createDiscoveryDocument = (
  overrides: Partial<OidcDiscoveryDocument> = {}
): OidcDiscoveryDocument => ({
  issuer: TEST_ISSUER,
  authorization_endpoint: TEST_AUTHORIZATION_ENDPOINT,
  token_endpoint: TEST_TOKEN_ENDPOINT,
  jwks_uri: TEST_JWKS_URI,
  introspection_endpoint: TEST_INTROSPECTION_ENDPOINT,
  response_types_supported: ['code', 'token'],
  grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
  scopes_supported: [...ALL_SCOPES],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  ...overrides,
});

/**
 * Creates authentication info from discovery document.
 */
export const createAuthenticationInfo = (
  overrides: Partial<AuthenticationInfo> = {}
): AuthenticationInfo => ({
  authorizationEndpoint: TEST_AUTHORIZATION_ENDPOINT,
  tokenEndpoint: TEST_TOKEN_ENDPOINT,
  issuer: TEST_ISSUER,
  supportedScopes: [...ALL_SCOPES],
  ...overrides,
});

// ============================================================================
// JWT Claims Fixtures
// ============================================================================

/**
 * Creates valid JWT claims for testing.
 * Expiration is set to 1 hour from the fixed timestamp.
 */
export const createValidClaims = (overrides: Record<string, unknown> = {}): TokenClaims => ({
  sub: TEST_SUBJECT,
  iss: TEST_ISSUER,
  aud: TEST_AUDIENCE,
  exp: FIXED_TIMESTAMP_SECONDS + ONE_HOUR_MS / 1000,
  iat: FIXED_TIMESTAMP_SECONDS,
  jti: TEST_JWT_ID,
  scope: SCOPES_READ_WRITE,
  client_id: TEST_CLIENT_ID,
  ...overrides,
});

/**
 * Creates expired JWT claims for testing.
 * Expiration is set to 1 hour before the fixed timestamp.
 */
export const createExpiredClaims = (overrides: Record<string, unknown> = {}): TokenClaims =>
  createValidClaims({
    exp: FIXED_TIMESTAMP_SECONDS - ONE_HOUR_MS / 1000,
    ...overrides,
  });

// ============================================================================
// Error Messages
// ============================================================================

export const ERROR_MESSAGES = {
  MISSING_TOKEN: 'No access token provided',
  MALFORMED_TOKEN: 'Token is not a valid JWT',
  EXPIRED_TOKEN: 'Token has expired',
  INVALID_SIGNATURE: 'Token signature verification failed',
  INVALID_ISSUER: 'Token issuer is invalid',
  INVALID_AUDIENCE: 'Token audience is invalid',
  INSUFFICIENT_SCOPE: 'Missing required scopes',
} as const;
