/**
 * Client ID Metadata Document module.
 *
 * Provides types and utilities for OAuth 2.0 client metadata documents
 * per the MCP authorization specification.
 *
 * @packageDocumentation
 */

// Types
export type {
  GrantType,
  ResponseType,
  TokenEndpointAuthMethod,
  ClientMetadataDocument,
  ClientMetadataErrorCode,
  ClientMetadataError,
  ClientMetadataOptions,
  ClientMetadataFetchResult,
  FetchClientMetadataOptions,
} from './types.js';

// Functions
export {
  validateClientIdUrl,
  validateRedirectUri,
  validateClientMetadataDocument,
  buildClientMetadataDocument,
  fetchClientMetadataDocument,
  isUrlBasedClientId,
  serializeClientMetadataDocument,
} from './client-metadata.js';
