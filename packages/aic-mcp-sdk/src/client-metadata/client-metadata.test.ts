import { describe, it, expect } from 'vitest';
import {
  validateClientIdUrl,
  validateRedirectUri,
  validateClientMetadataDocument,
  buildClientMetadataDocument,
  fetchClientMetadataDocument,
  isUrlBasedClientId,
  serializeClientMetadataDocument,
} from './client-metadata.js';
import type { ClientMetadataDocument } from './types.js';
import type { HttpClient } from '../http/types.js';

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Creates a mock HTTP client that returns a successful response.
 */
const createSuccessHttpClient = (body: unknown, status = 200): HttpClient => ({
  json: () =>
    Promise.resolve({
      isOk: () => true as const,
      isErr: () => false as const,
      value: { body, status, headers: {} },
      error: undefined as never,
    }),
  form: () => Promise.reject(new Error('Not implemented')),
});

/**
 * Creates a mock HTTP client that returns an error.
 */
const createErrorHttpClient = (message: string): HttpClient => ({
  json: () =>
    Promise.resolve({
      isOk: () => false as const,
      isErr: () => true as const,
      value: undefined as never,
      error: { message, code: 'FETCH_ERROR' },
    }),
  form: () => Promise.reject(new Error('Not implemented')),
});

/**
 * Creates a valid client metadata document for testing.
 */
const createValidDocument = (
  overrides: Partial<ClientMetadataDocument> = {}
): ClientMetadataDocument => ({
  client_id: 'https://app.example.com/oauth/client-metadata.json',
  client_name: 'Test MCP Client',
  redirect_uris: ['http://127.0.0.1:3000/callback'],
  grant_types: ['authorization_code'],
  response_types: ['code'],
  token_endpoint_auth_method: 'none',
  ...overrides,
});

// ============================================================================
// validateClientIdUrl Tests
// ============================================================================

describe('validateClientIdUrl', () => {
  describe('given valid HTTPS URL with path', () => {
    it('validateClientIdUrl_ValidHttpsUrl_ReturnsOk', () => {
      // Arrange
      const url = 'https://app.example.com/oauth/client-metadata.json';

      // Act
      const result = validateClientIdUrl(url);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.href).toBe(url);
      }
    });

    it('validateClientIdUrl_UrlWithQueryParams_ReturnsOk', () => {
      // Arrange
      const url = 'https://app.example.com/client?version=1';

      // Act
      const result = validateClientIdUrl(url);

      // Assert
      expect(result.isOk()).toBe(true);
    });
  });

  describe('given HTTP URL', () => {
    it('validateClientIdUrl_HttpUrl_ReturnsError', () => {
      // Arrange
      const url = 'http://app.example.com/oauth/client-metadata.json';

      // Act
      const result = validateClientIdUrl(url);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_CLIENT_ID_URL');
        expect(result.error.message).toContain('HTTPS');
      }
    });
  });

  describe('given URL without path', () => {
    it('validateClientIdUrl_NoPath_ReturnsError', () => {
      // Arrange
      const url = 'https://app.example.com';

      // Act
      const result = validateClientIdUrl(url);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_CLIENT_ID_URL');
        expect(result.error.message).toContain('path component');
      }
    });

    it('validateClientIdUrl_OnlySlash_ReturnsError', () => {
      // Arrange
      const url = 'https://app.example.com/';

      // Act
      const result = validateClientIdUrl(url);

      // Assert
      expect(result.isErr()).toBe(true);
    });
  });

  describe('given invalid URL', () => {
    it('validateClientIdUrl_InvalidUrl_ReturnsError', () => {
      // Arrange
      const url = 'not-a-url';

      // Act
      const result = validateClientIdUrl(url);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_CLIENT_ID_URL');
        expect(result.error.message).toContain('Invalid URL');
      }
    });
  });
});

// ============================================================================
// validateRedirectUri Tests
// ============================================================================

describe('validateRedirectUri', () => {
  describe('given valid localhost URI', () => {
    it('validateRedirectUri_Http127001_ReturnsOk', () => {
      // Arrange
      const uri = 'http://127.0.0.1:3000/callback';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isOk()).toBe(true);
    });

    it('validateRedirectUri_HttpLocalhost_ReturnsOk', () => {
      // Arrange
      const uri = 'http://localhost:8080/callback';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isOk()).toBe(true);
    });

    it('validateRedirectUri_HttpIpv6Loopback_ReturnsOk', () => {
      // Arrange
      const uri = 'http://[::1]:3000/callback';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isOk()).toBe(true);
    });
  });

  describe('given HTTPS URI', () => {
    it('validateRedirectUri_HttpsUri_ReturnsOk', () => {
      // Arrange
      const uri = 'https://app.example.com/callback';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isOk()).toBe(true);
    });
  });

  describe('given non-localhost HTTP URI', () => {
    it('validateRedirectUri_HttpNonLocalhost_ReturnsError', () => {
      // Arrange
      const uri = 'http://example.com/callback';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_REDIRECT_URI');
        expect(result.error.message).toContain('localhost');
      }
    });
  });

  describe('given invalid URI', () => {
    it('validateRedirectUri_InvalidUri_ReturnsError', () => {
      // Arrange
      const uri = 'not-a-uri';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_REDIRECT_URI');
      }
    });
  });

  describe('given non-HTTP/HTTPS scheme', () => {
    it('validateRedirectUri_CustomScheme_ReturnsError', () => {
      // Arrange
      const uri = 'myapp://callback';

      // Act
      const result = validateRedirectUri(uri);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('HTTP or HTTPS');
      }
    });
  });
});

// ============================================================================
// validateClientMetadataDocument Tests
// ============================================================================

describe('validateClientMetadataDocument', () => {
  describe('given valid document', () => {
    it('validateClientMetadataDocument_ValidDoc_ReturnsOk', () => {
      // Arrange
      const doc = createValidDocument();

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.client_id).toBe(doc.client_id);
        expect(result.value.client_name).toBe(doc.client_name);
      }
    });
  });

  describe('given null or non-object', () => {
    it('validateClientMetadataDocument_Null_ReturnsError', () => {
      // Act
      const result = validateClientMetadataDocument(null);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_DOCUMENT');
      }
    });

    it('validateClientMetadataDocument_String_ReturnsError', () => {
      // Act
      const result = validateClientMetadataDocument('not an object');

      // Assert
      expect(result.isErr()).toBe(true);
    });
  });

  describe('given missing required fields', () => {
    it('validateClientMetadataDocument_MissingClientId_ReturnsError', () => {
      // Arrange
      const doc = { client_name: 'Test', redirect_uris: ['http://127.0.0.1:3000/callback'] };

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('MISSING_REQUIRED_FIELD');
        expect(result.error.message).toContain('client_id');
      }
    });

    it('validateClientMetadataDocument_MissingClientName_ReturnsError', () => {
      // Arrange
      const doc = {
        client_id: 'https://app.example.com/client.json',
        redirect_uris: ['http://127.0.0.1:3000/callback'],
      };

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('client_name');
      }
    });

    it('validateClientMetadataDocument_MissingRedirectUris_ReturnsError', () => {
      // Arrange
      const doc = {
        client_id: 'https://app.example.com/client.json',
        client_name: 'Test',
      };

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('redirect_uris');
      }
    });

    it('validateClientMetadataDocument_EmptyRedirectUris_ReturnsError', () => {
      // Arrange
      const doc = {
        client_id: 'https://app.example.com/client.json',
        client_name: 'Test',
        redirect_uris: [],
      };

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.message).toContain('at least one');
      }
    });
  });

  describe('given expectedUrl parameter', () => {
    it('validateClientMetadataDocument_MatchingUrl_ReturnsOk', () => {
      // Arrange
      const url = 'https://app.example.com/oauth/client-metadata.json';
      const doc = createValidDocument({ client_id: url });

      // Act
      const result = validateClientMetadataDocument(doc, url);

      // Assert
      expect(result.isOk()).toBe(true);
    });

    it('validateClientMetadataDocument_MismatchedUrl_ReturnsError', () => {
      // Arrange
      const url = 'https://app.example.com/oauth/client-metadata.json';
      const doc = createValidDocument({ client_id: 'https://other.example.com/client.json' });

      // Act
      const result = validateClientMetadataDocument(doc, url);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('CLIENT_ID_MISMATCH');
      }
    });
  });

  describe('given invalid redirect_uris', () => {
    it('validateClientMetadataDocument_NonStringUri_ReturnsError', () => {
      // Arrange
      const doc = {
        client_id: 'https://app.example.com/client.json',
        client_name: 'Test',
        redirect_uris: [123],
      };

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_REDIRECT_URI');
      }
    });

    it('validateClientMetadataDocument_InvalidUri_ReturnsError', () => {
      // Arrange
      const doc = {
        client_id: 'https://app.example.com/client.json',
        client_name: 'Test',
        redirect_uris: ['not-a-uri'],
      };

      // Act
      const result = validateClientMetadataDocument(doc);

      // Assert
      expect(result.isErr()).toBe(true);
    });
  });
});

// ============================================================================
// buildClientMetadataDocument Tests
// ============================================================================

describe('buildClientMetadataDocument', () => {
  describe('given valid options', () => {
    it('buildClientMetadataDocument_MinimalOptions_ReturnsDocWithDefaults', () => {
      // Arrange
      const options = {
        metadataUrl: 'https://app.example.com/oauth/client-metadata.json',
        clientName: 'My MCP Client',
        redirectUris: ['http://127.0.0.1:3000/callback'],
      };

      // Act
      const result = buildClientMetadataDocument(options);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.client_id).toBe(options.metadataUrl);
        expect(result.value.client_name).toBe(options.clientName);
        expect(result.value.redirect_uris).toEqual(options.redirectUris);
        expect(result.value.grant_types).toEqual(['authorization_code']);
        expect(result.value.response_types).toEqual(['code']);
        expect(result.value.token_endpoint_auth_method).toBe('none');
      }
    });

    it('buildClientMetadataDocument_AllOptions_ReturnsCompleteDoc', () => {
      // Arrange
      const options = {
        metadataUrl: 'https://app.example.com/oauth/client-metadata.json',
        clientName: 'My MCP Client',
        redirectUris: ['http://127.0.0.1:3000/callback', 'http://localhost:3000/callback'],
        grantTypes: ['authorization_code', 'refresh_token'] as const,
        responseTypes: ['code'] as const,
        tokenEndpointAuthMethod: 'private_key_jwt' as const,
        clientUri: 'https://app.example.com',
        logoUri: 'https://app.example.com/logo.png',
        tosUri: 'https://app.example.com/tos',
        policyUri: 'https://app.example.com/privacy',
        jwksUri: 'https://app.example.com/.well-known/jwks.json',
        softwareId: 'my-mcp-client',
        softwareVersion: '1.0.0',
        scope: 'openid profile email',
        contacts: ['dev@example.com'],
      };

      // Act
      const result = buildClientMetadataDocument(options);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.client_uri).toBe(options.clientUri);
        expect(result.value.logo_uri).toBe(options.logoUri);
        expect(result.value.tos_uri).toBe(options.tosUri);
        expect(result.value.policy_uri).toBe(options.policyUri);
        expect(result.value.jwks_uri).toBe(options.jwksUri);
        expect(result.value.software_id).toBe(options.softwareId);
        expect(result.value.software_version).toBe(options.softwareVersion);
        expect(result.value.scope).toBe(options.scope);
        expect(result.value.contacts).toEqual(options.contacts);
      }
    });
  });

  describe('given invalid options', () => {
    it('buildClientMetadataDocument_InvalidMetadataUrl_ReturnsError', () => {
      // Arrange
      const options = {
        metadataUrl: 'http://app.example.com/client.json', // HTTP not HTTPS
        clientName: 'Test',
        redirectUris: ['http://127.0.0.1:3000/callback'],
      };

      // Act
      const result = buildClientMetadataDocument(options);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_CLIENT_ID_URL');
      }
    });

    it('buildClientMetadataDocument_InvalidRedirectUri_ReturnsError', () => {
      // Arrange
      const options = {
        metadataUrl: 'https://app.example.com/client.json',
        clientName: 'Test',
        redirectUris: ['http://external.example.com/callback'], // Non-localhost HTTP
      };

      // Act
      const result = buildClientMetadataDocument(options);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_REDIRECT_URI');
      }
    });
  });
});

// ============================================================================
// fetchClientMetadataDocument Tests
// ============================================================================

describe('fetchClientMetadataDocument', () => {
  const validUrl = 'https://app.example.com/oauth/client-metadata.json';

  describe('given successful fetch with valid document', () => {
    it('fetchClientMetadataDocument_ValidResponse_ReturnsDocument', async () => {
      // Arrange
      const doc = createValidDocument({ client_id: validUrl });
      const httpClient = createSuccessHttpClient(doc);

      // Act
      const result = await fetchClientMetadataDocument(httpClient, validUrl);

      // Assert
      expect(result.isOk()).toBe(true);
      if (result.isOk()) {
        expect(result.value.document.client_id).toBe(validUrl);
        expect(result.value.url).toBe(validUrl);
        expect(result.value.status).toBe(200);
      }
    });
  });

  describe('given fetch error', () => {
    it('fetchClientMetadataDocument_FetchError_ReturnsError', async () => {
      // Arrange
      const httpClient = createErrorHttpClient('Network error');

      // Act
      const result = await fetchClientMetadataDocument(httpClient, validUrl);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('FETCH_ERROR');
        expect(result.error.message).toContain('Network error');
      }
    });
  });

  describe('given HTTP error status', () => {
    it('fetchClientMetadataDocument_Http404_ReturnsError', async () => {
      // Arrange
      const httpClient = createSuccessHttpClient({}, 404);

      // Act
      const result = await fetchClientMetadataDocument(httpClient, validUrl);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('FETCH_ERROR');
        expect(result.error.message).toContain('404');
      }
    });
  });

  describe('given invalid URL', () => {
    it('fetchClientMetadataDocument_InvalidUrl_ReturnsError', async () => {
      // Arrange
      const httpClient = createSuccessHttpClient({});

      // Act
      const result = await fetchClientMetadataDocument(httpClient, 'not-a-url');

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('INVALID_CLIENT_ID_URL');
      }
    });
  });

  describe('given mismatched client_id', () => {
    it('fetchClientMetadataDocument_MismatchedClientId_ReturnsError', async () => {
      // Arrange
      const doc = createValidDocument({ client_id: 'https://other.example.com/client.json' });
      const httpClient = createSuccessHttpClient(doc);

      // Act
      const result = await fetchClientMetadataDocument(httpClient, validUrl);

      // Assert
      expect(result.isErr()).toBe(true);
      if (result.isErr()) {
        expect(result.error.code).toBe('CLIENT_ID_MISMATCH');
      }
    });
  });

  describe('given validateClientId disabled', () => {
    it('fetchClientMetadataDocument_ValidateDisabled_SkipsClientIdCheck', async () => {
      // Arrange
      const doc = createValidDocument({ client_id: 'https://other.example.com/client.json' });
      const httpClient = createSuccessHttpClient(doc);

      // Act
      const result = await fetchClientMetadataDocument(httpClient, validUrl, {
        validateClientId: false,
      });

      // Assert
      expect(result.isOk()).toBe(true);
    });
  });
});

// ============================================================================
// isUrlBasedClientId Tests
// ============================================================================

describe('isUrlBasedClientId', () => {
  describe('given HTTPS URL with path', () => {
    it('isUrlBasedClientId_ValidUrl_ReturnsTrue', () => {
      // Arrange
      const clientId = 'https://app.example.com/oauth/client-metadata.json';

      // Act
      const result = isUrlBasedClientId(clientId);

      // Assert
      expect(result).toBe(true);
    });
  });

  describe('given traditional client ID', () => {
    it('isUrlBasedClientId_OpaqueString_ReturnsFalse', () => {
      // Arrange
      const clientId = 'my-client-id-123';

      // Act
      const result = isUrlBasedClientId(clientId);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('given HTTP URL', () => {
    it('isUrlBasedClientId_HttpUrl_ReturnsFalse', () => {
      // Arrange
      const clientId = 'http://app.example.com/client.json';

      // Act
      const result = isUrlBasedClientId(clientId);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('given HTTPS URL without path', () => {
    it('isUrlBasedClientId_NoPath_ReturnsFalse', () => {
      // Arrange
      const clientId = 'https://app.example.com';

      // Act
      const result = isUrlBasedClientId(clientId);

      // Assert
      expect(result).toBe(false);
    });

    it('isUrlBasedClientId_OnlySlash_ReturnsFalse', () => {
      // Arrange
      const clientId = 'https://app.example.com/';

      // Act
      const result = isUrlBasedClientId(clientId);

      // Assert
      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// serializeClientMetadataDocument Tests
// ============================================================================

describe('serializeClientMetadataDocument', () => {
  it('serializeClientMetadataDocument_ValidDoc_ReturnsJsonString', () => {
    // Arrange
    const doc = createValidDocument();

    // Act
    const result = serializeClientMetadataDocument(doc);

    // Assert
    expect(typeof result).toBe('string');
    const parsed = JSON.parse(result) as ClientMetadataDocument;
    expect(parsed.client_id).toBe(doc.client_id);
    expect(parsed.client_name).toBe(doc.client_name);
  });

  it('serializeClientMetadataDocument_FormattedOutput_HasIndentation', () => {
    // Arrange
    const doc = createValidDocument();

    // Act
    const result = serializeClientMetadataDocument(doc);

    // Assert
    expect(result).toContain('\n');
    expect(result).toContain('  '); // 2-space indentation
  });
});
