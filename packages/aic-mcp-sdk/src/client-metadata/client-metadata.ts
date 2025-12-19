/**
 * Client ID Metadata Document utilities per MCP spec.
 *
 * Provides functions for creating, validating, and fetching
 * OAuth 2.0 client metadata documents.
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization
 * @packageDocumentation
 */

import { ok, err, type Result } from 'neverthrow';
import type { HttpClient } from '../http/types.js';
import type {
  ClientMetadataDocument,
  ClientMetadataError,
  ClientMetadataOptions,
  ClientMetadataFetchResult,
  FetchClientMetadataOptions,
} from './types.js';

/**
 * Creates an error for client metadata operations.
 */
const createError = (
  code: ClientMetadataError['code'],
  message: string,
  cause?: unknown
): ClientMetadataError => ({
  code,
  message,
  cause,
});

/**
 * Validates that a URL is a valid HTTPS URL with a path component.
 *
 * Per MCP spec, client_id URLs must:
 * - Use HTTPS scheme
 * - Have a path component (not just the origin)
 *
 * @param url - The URL to validate
 * @returns Result with the validated URL or error
 */
export const validateClientIdUrl = (url: string): Result<URL, ClientMetadataError> => {
  let parsed: URL;

  try {
    parsed = new URL(url);
  } catch {
    return err(createError('INVALID_CLIENT_ID_URL', `Invalid URL: ${url}`));
  }

  if (parsed.protocol !== 'https:') {
    return err(createError('INVALID_CLIENT_ID_URL', `Client ID URL must use HTTPS: ${url}`));
  }

  // Must have a path component (not just "/")
  if (parsed.pathname === '/' || parsed.pathname === '') {
    return err(
      createError('INVALID_CLIENT_ID_URL', `Client ID URL must have a path component: ${url}`)
    );
  }

  return ok(parsed);
};

/**
 * Validates a redirect URI.
 *
 * Per MCP spec, redirect URIs for public clients should typically
 * be localhost URLs (http://127.0.0.1 or http://localhost).
 *
 * @param uri - The redirect URI to validate
 * @returns Result with the validated URI or error
 */
export const validateRedirectUri = (uri: string): Result<URL, ClientMetadataError> => {
  let parsed: URL;

  try {
    parsed = new URL(uri);
  } catch {
    return err(createError('INVALID_REDIRECT_URI', `Invalid redirect URI: ${uri}`));
  }

  // Allow http for localhost/loopback addresses
  const isLoopback =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';

  if (parsed.protocol === 'http:' && !isLoopback) {
    return err(
      createError(
        'INVALID_REDIRECT_URI',
        `HTTP redirect URIs are only allowed for localhost: ${uri}`
      )
    );
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return err(createError('INVALID_REDIRECT_URI', `Redirect URI must use HTTP or HTTPS: ${uri}`));
  }

  return ok(parsed);
};

/**
 * Validates a client metadata document.
 *
 * Checks that:
 * - Required fields are present (client_id, client_name, redirect_uris)
 * - client_id is a valid HTTPS URL with path
 * - redirect_uris are valid URIs
 * - If expectedUrl is provided, client_id matches it
 *
 * @param doc - The document to validate
 * @param expectedUrl - Optional URL that client_id must match
 * @returns Result with validated document or error
 */
export const validateClientMetadataDocument = (
  doc: unknown,
  expectedUrl?: string
): Result<ClientMetadataDocument, ClientMetadataError> => {
  if (doc === null || typeof doc !== 'object') {
    return err(createError('INVALID_DOCUMENT', 'Client metadata document must be an object'));
  }

  const d = doc as Record<string, unknown>;

  // Required: client_id
  if (typeof d['client_id'] !== 'string') {
    return err(
      createError('MISSING_REQUIRED_FIELD', 'Client metadata document must include "client_id"')
    );
  }

  // Validate client_id is a valid HTTPS URL
  const clientIdResult = validateClientIdUrl(d['client_id']);
  if (clientIdResult.isErr()) {
    return err(clientIdResult.error);
  }

  // If expectedUrl provided, verify match
  if (expectedUrl !== undefined && d['client_id'] !== expectedUrl) {
    return err(
      createError(
        'CLIENT_ID_MISMATCH',
        `client_id "${d['client_id']}" does not match document URL "${expectedUrl}"`
      )
    );
  }

  // Required: client_name
  if (typeof d['client_name'] !== 'string') {
    return err(
      createError('MISSING_REQUIRED_FIELD', 'Client metadata document must include "client_name"')
    );
  }

  // Required: redirect_uris
  if (!Array.isArray(d['redirect_uris'])) {
    return err(
      createError(
        'MISSING_REQUIRED_FIELD',
        'Client metadata document must include "redirect_uris" array'
      )
    );
  }

  if (d['redirect_uris'].length === 0) {
    return err(
      createError(
        'MISSING_REQUIRED_FIELD',
        'Client metadata document must include at least one redirect_uri'
      )
    );
  }

  // Validate each redirect_uri
  for (const uri of d['redirect_uris']) {
    if (typeof uri !== 'string') {
      return err(createError('INVALID_REDIRECT_URI', 'redirect_uris must be an array of strings'));
    }
    const uriResult = validateRedirectUri(uri);
    if (uriResult.isErr()) {
      return err(uriResult.error);
    }
  }

  return ok(d as unknown as ClientMetadataDocument);
};

/**
 * Builds a client metadata document from options.
 *
 * @param options - Options for building the document
 * @returns Result with the built document or validation error
 *
 * @example
 * ```typescript
 * const result = buildClientMetadataDocument({
 *   metadataUrl: 'https://app.example.com/oauth/client-metadata.json',
 *   clientName: 'My MCP Client',
 *   redirectUris: ['http://127.0.0.1:3000/callback'],
 * });
 *
 * if (result.isOk()) {
 *   // Host result.value at the metadataUrl
 * }
 * ```
 */
export const buildClientMetadataDocument = (
  options: ClientMetadataOptions
): Result<ClientMetadataDocument, ClientMetadataError> => {
  // Validate metadata URL
  const urlResult = validateClientIdUrl(options.metadataUrl);
  if (urlResult.isErr()) {
    return err(urlResult.error);
  }

  // Validate redirect URIs
  for (const uri of options.redirectUris) {
    const uriResult = validateRedirectUri(uri);
    if (uriResult.isErr()) {
      return err(uriResult.error);
    }
  }

  const document: ClientMetadataDocument = {
    client_id: options.metadataUrl,
    client_name: options.clientName,
    redirect_uris: options.redirectUris,
    grant_types: options.grantTypes ?? ['authorization_code'],
    response_types: options.responseTypes ?? ['code'],
    token_endpoint_auth_method: options.tokenEndpointAuthMethod ?? 'none',
    ...(options.clientUri !== undefined && { client_uri: options.clientUri }),
    ...(options.logoUri !== undefined && { logo_uri: options.logoUri }),
    ...(options.tosUri !== undefined && { tos_uri: options.tosUri }),
    ...(options.policyUri !== undefined && { policy_uri: options.policyUri }),
    ...(options.jwksUri !== undefined && { jwks_uri: options.jwksUri }),
    ...(options.softwareId !== undefined && { software_id: options.softwareId }),
    ...(options.softwareVersion !== undefined && { software_version: options.softwareVersion }),
    ...(options.scope !== undefined && { scope: options.scope }),
    ...(options.contacts !== undefined && { contacts: options.contacts }),
  };

  return ok(document);
};

/**
 * Fetches and validates a client metadata document from a URL.
 *
 * Per MCP spec, authorization servers should fetch the client metadata
 * document from the client_id URL to verify client information.
 *
 * @param httpClient - HTTP client to use for fetching
 * @param url - The client_id URL to fetch from
 * @param options - Fetch options
 * @returns Result with the fetched document or error
 *
 * @example
 * ```typescript
 * const result = await fetchClientMetadataDocument(
 *   httpClient,
 *   'https://app.example.com/oauth/client-metadata.json'
 * );
 *
 * if (result.isOk()) {
 *   console.log('Client name:', result.value.document.client_name);
 * }
 * ```
 */
export const fetchClientMetadataDocument = async (
  httpClient: HttpClient,
  url: string,
  options: FetchClientMetadataOptions = {}
): Promise<Result<ClientMetadataFetchResult, ClientMetadataError>> => {
  const { validateClientId = true } = options;

  // First validate the URL format
  const urlResult = validateClientIdUrl(url);
  if (urlResult.isErr()) {
    return err(urlResult.error);
  }

  // Fetch the document
  const response = await httpClient.json<unknown>({
    url,
    method: 'GET',
  });

  if (response.isErr()) {
    return err(
      createError(
        'FETCH_ERROR',
        `Failed to fetch client metadata from ${url}: ${response.error.message}`,
        response.error
      )
    );
  }

  // Check for HTTP error status
  if (response.value.status >= 400) {
    return err(createError('FETCH_ERROR', `HTTP ${String(response.value.status)} from ${url}`));
  }

  // Validate the document
  const docResult = validateClientMetadataDocument(
    response.value.body,
    validateClientId ? url : undefined
  );

  if (docResult.isErr()) {
    return err(docResult.error);
  }

  return ok({
    document: docResult.value,
    url,
    status: response.value.status,
  });
};

/**
 * Checks if a client_id is a URL-based client ID (metadata document).
 *
 * URL-based client IDs start with "https://" and have a path component.
 * Traditional client IDs are opaque strings.
 *
 * @param clientId - The client ID to check
 * @returns True if the client ID is a URL-based metadata document reference
 *
 * @example
 * ```typescript
 * isUrlBasedClientId('https://app.example.com/client.json'); // true
 * isUrlBasedClientId('my-client-id'); // false
 * ```
 */
export const isUrlBasedClientId = (clientId: string): boolean => {
  if (!clientId.startsWith('https://')) {
    return false;
  }

  try {
    const url = new URL(clientId);
    return url.pathname !== '/' && url.pathname !== '';
  } catch {
    return false;
  }
};

/**
 * Serializes a client metadata document to JSON.
 *
 * @param document - The document to serialize
 * @returns JSON string representation
 */
export const serializeClientMetadataDocument = (document: ClientMetadataDocument): string => {
  return JSON.stringify(document, null, 2);
};
