/**
 * Client ID Metadata Document types per MCP spec.
 *
 * Defines types for OAuth 2.0 client metadata documents that can be
 * hosted at HTTPS URLs and used as client identifiers.
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization
 * @packageDocumentation
 */

/**
 * OAuth 2.0 grant types supported by the client.
 */
export type GrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials'
  | 'urn:ietf:params:oauth:grant-type:token-exchange';

/**
 * OAuth 2.0 response types supported by the client.
 */
export type ResponseType = 'code' | 'token';

/**
 * Token endpoint authentication methods.
 */
export type TokenEndpointAuthMethod =
  | 'none'
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'private_key_jwt';

/**
 * Client ID Metadata Document per MCP spec.
 *
 * This document is hosted at an HTTPS URL and the URL itself
 * serves as the client_id. The document must include required
 * fields and the client_id must exactly match the document URL.
 *
 * @example
 * ```typescript
 * const metadata: ClientMetadataDocument = {
 *   client_id: 'https://app.example.com/oauth/client-metadata.json',
 *   client_name: 'My MCP Client',
 *   redirect_uris: ['http://127.0.0.1:3000/callback'],
 *   grant_types: ['authorization_code', 'refresh_token'],
 *   response_types: ['code'],
 *   token_endpoint_auth_method: 'none',
 * };
 * ```
 */
export interface ClientMetadataDocument {
  /**
   * Client identifier (REQUIRED).
   * Must be an HTTPS URL that exactly matches the document's URL.
   */
  readonly client_id: string;

  /**
   * Human-readable name of the client (REQUIRED).
   */
  readonly client_name: string;

  /**
   * Array of allowed redirect URIs (REQUIRED).
   * For public clients, typically includes localhost variants.
   */
  readonly redirect_uris: readonly string[];

  /**
   * OAuth 2.0 grant types the client will use.
   * @default ['authorization_code']
   */
  readonly grant_types?: readonly GrantType[];

  /**
   * OAuth 2.0 response types the client will use.
   * @default ['code']
   */
  readonly response_types?: readonly ResponseType[];

  /**
   * Token endpoint authentication method.
   * @default 'none' for public clients
   */
  readonly token_endpoint_auth_method?: TokenEndpointAuthMethod;

  /**
   * URL of the client's home page.
   */
  readonly client_uri?: string;

  /**
   * URL of the client's logo image.
   */
  readonly logo_uri?: string;

  /**
   * URL of the client's terms of service.
   */
  readonly tos_uri?: string;

  /**
   * URL of the client's privacy policy.
   */
  readonly policy_uri?: string;

  /**
   * URL of the client's JWKS for private_key_jwt authentication.
   * Required when token_endpoint_auth_method is 'private_key_jwt'.
   */
  readonly jwks_uri?: string;

  /**
   * Software identifier for the client.
   */
  readonly software_id?: string;

  /**
   * Software version string.
   */
  readonly software_version?: string;

  /**
   * Array of scopes the client may request.
   */
  readonly scope?: string;

  /**
   * Array of contacts for the client (email addresses).
   */
  readonly contacts?: readonly string[];
}

/**
 * Error codes for client metadata operations.
 */
export type ClientMetadataErrorCode =
  | 'INVALID_CLIENT_ID_URL'
  | 'FETCH_ERROR'
  | 'INVALID_DOCUMENT'
  | 'CLIENT_ID_MISMATCH'
  | 'MISSING_REQUIRED_FIELD'
  | 'INVALID_REDIRECT_URI';

/**
 * Error from client metadata operations.
 */
export interface ClientMetadataError {
  /** Error code for programmatic handling */
  readonly code: ClientMetadataErrorCode;
  /** Human-readable error message */
  readonly message: string;
  /** Original error if available */
  readonly cause?: unknown;
}

/**
 * Options for building a client metadata document.
 */
export interface ClientMetadataOptions {
  /**
   * The URL where this metadata document will be hosted.
   * This becomes the client_id.
   */
  readonly metadataUrl: string;

  /**
   * Human-readable name of the client.
   */
  readonly clientName: string;

  /**
   * Allowed redirect URIs.
   */
  readonly redirectUris: readonly string[];

  /**
   * OAuth 2.0 grant types the client will use.
   * @default ['authorization_code']
   */
  readonly grantTypes?: readonly GrantType[];

  /**
   * OAuth 2.0 response types the client will use.
   * @default ['code']
   */
  readonly responseTypes?: readonly ResponseType[];

  /**
   * Token endpoint authentication method.
   * @default 'none'
   */
  readonly tokenEndpointAuthMethod?: TokenEndpointAuthMethod;

  /**
   * URL of the client's home page.
   */
  readonly clientUri?: string;

  /**
   * URL of the client's logo image.
   */
  readonly logoUri?: string;

  /**
   * URL of the client's terms of service.
   */
  readonly tosUri?: string;

  /**
   * URL of the client's privacy policy.
   */
  readonly policyUri?: string;

  /**
   * URL of the client's JWKS for private_key_jwt authentication.
   */
  readonly jwksUri?: string;

  /**
   * Software identifier for the client.
   */
  readonly softwareId?: string;

  /**
   * Software version string.
   */
  readonly softwareVersion?: string;

  /**
   * Space-separated scopes the client may request.
   */
  readonly scope?: string;

  /**
   * Array of contacts for the client (email addresses).
   */
  readonly contacts?: readonly string[];
}

/**
 * Result of fetching a client metadata document.
 */
export interface ClientMetadataFetchResult {
  /** The fetched and validated metadata document */
  readonly document: ClientMetadataDocument;
  /** The URL the document was fetched from */
  readonly url: string;
  /** HTTP status code */
  readonly status: number;
}

/**
 * Options for fetching client metadata.
 */
export interface FetchClientMetadataOptions {
  /**
   * Timeout in milliseconds for the fetch request.
   * @default 10000
   */
  readonly timeoutMs?: number;

  /**
   * Whether to validate that the client_id matches the URL.
   * @default true
   */
  readonly validateClientId?: boolean;
}
