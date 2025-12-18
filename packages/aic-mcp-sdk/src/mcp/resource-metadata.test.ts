import { describe, it, expect } from 'vitest';
import {
  createProtectedResourceMetadata,
  formatWwwAuthenticateHeader,
  parseWwwAuthenticateHeader,
} from './resource-metadata.js';

describe('createProtectedResourceMetadata', () => {
  describe('given minimal required config', () => {
    it('returns metadata with resource and authorization_servers', () => {
      const result = createProtectedResourceMetadata({
        resourceUrl: 'https://mcp.example.com',
        authorizationServers: 'https://auth.example.com',
      });

      expect(result).toEqual({
        resource: 'https://mcp.example.com',
        authorization_servers: ['https://auth.example.com'],
        bearer_methods_supported: ['header'],
      });
    });
  });

  describe('given authorization servers as array', () => {
    it('preserves the array format', () => {
      const result = createProtectedResourceMetadata({
        resourceUrl: 'https://mcp.example.com',
        authorizationServers: ['https://auth1.example.com', 'https://auth2.example.com'],
      });

      expect(result.authorization_servers).toEqual([
        'https://auth1.example.com',
        'https://auth2.example.com',
      ]);
    });
  });

  describe('given scopes supported', () => {
    it('includes scopes_supported in metadata', () => {
      const result = createProtectedResourceMetadata({
        resourceUrl: 'https://mcp.example.com',
        authorizationServers: 'https://auth.example.com',
        scopesSupported: ['openid', 'mcp:tools', 'mcp:resources'],
      });

      expect(result.scopes_supported).toEqual(['openid', 'mcp:tools', 'mcp:resources']);
    });
  });

  describe('given documentation URL', () => {
    it('includes resource_documentation in metadata', () => {
      const result = createProtectedResourceMetadata({
        resourceUrl: 'https://mcp.example.com',
        authorizationServers: 'https://auth.example.com',
        documentationUrl: 'https://docs.example.com/mcp',
      });

      expect(result.resource_documentation).toBe('https://docs.example.com/mcp');
    });
  });

  describe('given resource name', () => {
    it('includes resource_name in metadata', () => {
      const result = createProtectedResourceMetadata({
        resourceUrl: 'https://mcp.example.com',
        authorizationServers: 'https://auth.example.com',
        resourceName: 'My MCP Server',
      });

      expect(result.resource_name).toBe('My MCP Server');
    });
  });

  describe('given all optional fields', () => {
    it('includes all fields in metadata', () => {
      const result = createProtectedResourceMetadata({
        resourceUrl: 'https://mcp.example.com',
        authorizationServers: 'https://auth.example.com',
        scopesSupported: ['openid', 'profile'],
        documentationUrl: 'https://docs.example.com',
        resourceName: 'Test Server',
      });

      expect(result).toEqual({
        resource: 'https://mcp.example.com',
        authorization_servers: ['https://auth.example.com'],
        bearer_methods_supported: ['header'],
        scopes_supported: ['openid', 'profile'],
        resource_documentation: 'https://docs.example.com',
        resource_name: 'Test Server',
      });
    });
  });
});

describe('formatWwwAuthenticateHeader', () => {
  describe('given minimal config with only resourceMetadataUrl', () => {
    it('returns Bearer scheme with resource_metadata parameter', () => {
      const result = formatWwwAuthenticateHeader({
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
      });

      expect(result).toBe(
        'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
      );
    });
  });

  describe('given realm parameter', () => {
    it('includes realm before resource_metadata', () => {
      const result = formatWwwAuthenticateHeader({
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
        realm: 'mcp',
      });

      expect(result).toBe(
        'Bearer realm="mcp", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
      );
    });
  });

  describe('given scope parameter', () => {
    it('includes scope after resource_metadata', () => {
      const result = formatWwwAuthenticateHeader({
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
        scope: 'openid mcp:tools',
      });

      expect(result).toBe(
        'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="openid mcp:tools"'
      );
    });
  });

  describe('given error parameter', () => {
    it('includes error in header', () => {
      const result = formatWwwAuthenticateHeader({
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
        error: 'invalid_token',
      });

      expect(result).toContain('error="invalid_token"');
    });
  });

  describe('given error description', () => {
    it('includes error_description in header', () => {
      const result = formatWwwAuthenticateHeader({
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
        error: 'invalid_token',
        errorDescription: 'The token has expired',
      });

      expect(result).toContain('error_description="The token has expired"');
    });
  });

  describe('given DPoP scheme', () => {
    it('uses DPoP instead of Bearer', () => {
      const result = formatWwwAuthenticateHeader({
        scheme: 'DPoP',
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
      });

      expect(result.startsWith('DPoP ')).toBe(true);
    });
  });

  describe('given all parameters', () => {
    it('formats complete header correctly', () => {
      const result = formatWwwAuthenticateHeader({
        scheme: 'Bearer',
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
        realm: 'mcp',
        scope: 'openid',
        error: 'insufficient_scope',
        errorDescription: 'Missing required scope',
      });

      expect(result).toBe(
        'Bearer realm="mcp", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="openid", error="insufficient_scope", error_description="Missing required scope"'
      );
    });
  });
});

describe('parseWwwAuthenticateHeader', () => {
  describe('given valid Bearer header with resource_metadata', () => {
    it('parses scheme and resourceMetadataUrl', () => {
      const result = parseWwwAuthenticateHeader(
        'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
      );

      expect(result).toEqual({
        scheme: 'Bearer',
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
      });
    });
  });

  describe('given header with realm', () => {
    it('parses realm parameter', () => {
      const result = parseWwwAuthenticateHeader(
        'Bearer realm="mcp", resource_metadata="https://example.com/.well-known/oauth-protected-resource"'
      );

      expect(result?.realm).toBe('mcp');
    });
  });

  describe('given header with scope', () => {
    it('parses scope parameter', () => {
      const result = parseWwwAuthenticateHeader(
        'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", scope="openid profile"'
      );

      expect(result?.scope).toBe('openid profile');
    });
  });

  describe('given header with error', () => {
    it('parses error parameter', () => {
      const result = parseWwwAuthenticateHeader(
        'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", error="invalid_token"'
      );

      expect(result?.error).toBe('invalid_token');
    });
  });

  describe('given header with error_description', () => {
    it('parses errorDescription parameter', () => {
      const result = parseWwwAuthenticateHeader(
        'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", error_description="Token expired"'
      );

      expect(result?.errorDescription).toBe('Token expired');
    });
  });

  describe('given DPoP scheme', () => {
    it('parses DPoP scheme correctly', () => {
      const result = parseWwwAuthenticateHeader(
        'DPoP resource_metadata="https://example.com/.well-known/oauth-protected-resource"'
      );

      expect(result?.scheme).toBe('DPoP');
    });
  });

  describe('given invalid scheme', () => {
    it('returns undefined', () => {
      const result = parseWwwAuthenticateHeader(
        'Basic resource_metadata="https://example.com/.well-known/oauth-protected-resource"'
      );

      expect(result).toBeUndefined();
    });
  });

  describe('given missing resource_metadata', () => {
    it('returns undefined', () => {
      const result = parseWwwAuthenticateHeader('Bearer realm="mcp"');

      expect(result).toBeUndefined();
    });
  });

  describe('given empty string', () => {
    it('returns undefined', () => {
      const result = parseWwwAuthenticateHeader('');

      expect(result).toBeUndefined();
    });
  });

  describe('roundtrip format then parse', () => {
    it('parses what formatWwwAuthenticateHeader produces', () => {
      const original = {
        scheme: 'Bearer' as const,
        resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
        realm: 'mcp',
        scope: 'openid',
      };

      const header = formatWwwAuthenticateHeader(original);
      const parsed = parseWwwAuthenticateHeader(header);

      expect(parsed).toEqual(original);
    });
  });
});
