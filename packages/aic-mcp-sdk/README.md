# @pingidentity/aic-mcp-sdk

Authentication SDK for MCP (Model Context Protocol) servers integrating with PingOne Advanced Identity Cloud (AIC).

## Features

- **JWT Validation** - Verify RS256-signed JWTs using JWKS from OIDC discovery
- **Token Introspection** - RFC 7662 introspection for opaque tokens
- **Token Revocation** - RFC 7009 token revocation support
- **MCP Integration** - `withAuth` wrapper for protecting MCP tools
- **RFC 9728 Compliance** - Protected Resource Metadata for MCP-compliant 401 responses
- **Scope Validation** - Fine-grained access control with scope checking

## Installation

```bash
npm install @pingidentity/aic-mcp-sdk
# or
pnpm add @pingidentity/aic-mcp-sdk
```

## Quick Start

### Basic Token Validation

```typescript
import { createTokenValidator } from '@pingidentity/aic-mcp-sdk';

const validator = createTokenValidator({
  amUrl: 'https://openam-example.forgeblocks.com',
  clientId: 'my-mcp-server',
});

const result = await validator.validate(accessToken);

if (result.valid) {
  console.log('User:', result.claims.sub);
  console.log('Scopes:', result.claims.scope);
} else {
  console.error('Validation failed:', result.error, result.message);
}
```

### Protecting MCP Tools with `withAuth`

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createTokenValidator, createWithAuth } from '@pingidentity/aic-mcp-sdk';

// Create validator and auth wrapper
const validator = createTokenValidator({
  amUrl: process.env.AM_URL,
  clientId: process.env.AM_CLIENT_ID,
});

const withAuth = createWithAuth({ validator });

// Register protected tool
server.registerTool(
  'get_user_data',
  { description: 'Get user data', inputSchema: { ... } },
  withAuth({ requiredScopes: ['user:read'] }, async (args, extra) => {
    // extra.authInfo is guaranteed to exist here
    const userId = extra.authInfo.extra?.sub;

    return {
      content: [{ type: 'text', text: `User: ${userId}` }],
    };
  })
);
```

## Configuration

### Token Validator Options

```typescript
interface TokenValidatorConfig {
  /** Base URL of the AM instance (e.g., "https://openam-example.forgeblocks.com") */
  amUrl: string;

  /** OAuth client ID registered in AM */
  clientId: string;

  /** OAuth client secret (required for token introspection of opaque tokens) */
  clientSecret?: string;

  /** OAuth realm path (default: "/am/oauth2/realms/root/realms/alpha") */
  realmPath?: string;

  /** Discovery document cache TTL in ms (default: 3600000 = 1 hour) */
  discoveryCacheTtlMs?: number;
}
```

### Validation Options

```typescript
interface ValidationOptions {
  /** Required scopes that must be present in the token */
  requiredScopes?: readonly string[];

  /** Expected audience value(s) - defaults to clientId */
  audience?: string | readonly string[];

  /** Clock tolerance in seconds for exp/nbf validation (default: 15, recommended: 5-30) */
  clockToleranceSeconds?: number;
}
```

## API Reference

### Token Validation

#### `createTokenValidator(config)`

Creates a token validator instance.

```typescript
const validator = createTokenValidator({
  amUrl: 'https://openam-example.forgeblocks.com',
  clientId: 'my-client',
  clientSecret: 'my-secret', // Optional, enables opaque token introspection
});
```

#### `validator.validate(token, options?)`

Validates a token (JWT or opaque) and returns a discriminated union result.

```typescript
const result = await validator.validate(token, {
  requiredScopes: ['openid', 'profile'],
  clockToleranceSeconds: 30,
});

if (result.valid) {
  // TokenValidationSuccess
  console.log(result.claims.sub);
  console.log(result.claims.iss);
  console.log(result.accessToken);
} else {
  // TokenValidationFailure
  console.log(result.error);   // 'EXPIRED_TOKEN', 'INVALID_SIGNATURE', etc.
  console.log(result.message);
  console.log(result.authenticationInfo); // For 401 responses
}
```

#### `validator.getAuthenticationInfo()`

Gets authorization server metadata for 401 responses.

```typescript
const authInfo = await validator.getAuthenticationInfo();
// { authorizationEndpoint, tokenEndpoint, issuer, supportedScopes }
```

#### `validator.refreshCache()`

Forces a refresh of the cached OIDC discovery document and JWKS.

```typescript
await validator.refreshCache();
```

### MCP Integration

#### `createWithAuth(config)`

Creates a `withAuth` wrapper for protecting MCP tool handlers.

```typescript
import { createWithAuth, AuthenticationError, AuthorizationError } from '@pingidentity/aic-mcp-sdk';

const withAuth = createWithAuth({
  validator,
  tokenExtractor: {
    envVar: 'AM_ACCESS_TOKEN',        // Environment variable name
    metaField: 'accessToken',          // Request _meta field name
    stdioTokenSource: 'both',          // 'env' | 'meta' | 'both'
  },
});

// Protect a tool handler
const protectedHandler = withAuth(
  { requiredScopes: ['read', 'write'] },
  async (args, extra) => {
    // extra.authInfo contains validated token info
    const { token, clientId, scopes, expiresAt, extra: claims } = extra.authInfo;
    return { content: [{ type: 'text', text: 'Success' }] };
  }
);
```

#### Error Classes

```typescript
// Thrown on authentication failure (HTTP 401)
class AuthenticationError extends Error {
  code: string;                          // 'MISSING_TOKEN', 'EXPIRED_TOKEN', etc.
  authenticationInfo?: AuthenticationInfo;
  httpStatusCode: 401;
}

// Thrown on authorization failure (HTTP 403)
class AuthorizationError extends Error {
  requiredScopes: readonly string[];
  presentScopes: readonly string[];
  missingScopes: readonly string[];
  httpStatusCode: 403;
}
```

### RFC 9728 Protected Resource Metadata

For MCP-compliant 401 responses:

```typescript
import {
  createProtectedResourceMetadata,
  formatWwwAuthenticateHeader,
  parseWwwAuthenticateHeader,
} from '@pingidentity/aic-mcp-sdk';

// Create protected resource metadata
const metadata = createProtectedResourceMetadata({
  resourceUrl: 'https://mcp.example.com',
  authorizationServers: 'https://auth.example.com/oauth2',
  scopesSupported: ['openid', 'profile', 'todos:read'],
  resourceName: 'My MCP Server',
});

// Format WWW-Authenticate header
const header = formatWwwAuthenticateHeader({
  resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
  error: 'invalid_token',
  errorDescription: 'Token has expired',
});
// => 'Bearer resource_metadata="https://...", error="invalid_token", error_description="Token has expired"'

// Parse WWW-Authenticate header
const parsed = parseWwwAuthenticateHeader(header);
// => { scheme: 'Bearer', resourceMetadataUrl: '...', error: '...', errorDescription: '...' }
```

### Scope Utilities

```typescript
import { parseScopes, getMissingScopes } from '@pingidentity/aic-mcp-sdk';

// Parse scope string or array
const scopes = parseScopes('openid profile email');
// => ['openid', 'profile', 'email']

const scopes2 = parseScopes(['read', 'write']);
// => ['read', 'write']

// Check for missing scopes
const missing = getMissingScopes(['admin', 'read'], ['read', 'write']);
// => ['admin']
```

### Custom HTTP Client & Cache

For advanced use cases, you can provide custom implementations:

```typescript
import {
  createTokenValidator,
  createFetchClient,
  createMemoryCache,
  type HttpClient,
  type Cache,
} from '@pingidentity/aic-mcp-sdk';

// Custom HTTP client (e.g., with retry logic)
const customHttpClient: HttpClient = createFetchClient({
  timeout: 10000,
});

// Custom cache (e.g., Redis-backed)
const customCache: Cache<OidcDiscoveryDocument> = createMemoryCache(
  60 * 60 * 1000 // 1 hour TTL
);

const validator = createTokenValidator(
  { amUrl, clientId },
  customHttpClient,
  customCache
);
```

## Token Validation Flow

1. **Check token exists** → Returns `MISSING_TOKEN` if empty
2. **Detect token format** → JWT (3 dot-separated parts) or opaque
3. **For JWTs:**
   - Fetch OIDC discovery document (cached 1 hour)
   - Verify signature against JWKS
   - Validate claims (exp, iss, aud)
   - Check required scopes
4. **For opaque tokens:**
   - Requires `clientSecret` in config
   - Calls RFC 7662 introspection endpoint
   - Validates `active` status and scopes

## Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `MISSING_TOKEN` | No token provided | 401 |
| `MALFORMED_TOKEN` | Token format invalid or missing required claims | 401 |
| `EXPIRED_TOKEN` | Token has expired | 401 |
| `INVALID_SIGNATURE` | JWT signature verification failed | 401 |
| `INVALID_ISSUER` | Token issuer doesn't match expected | 401 |
| `INVALID_AUDIENCE` | Token audience doesn't match expected | 401 |
| `REVOKED_TOKEN` | Token has been revoked (introspection) | 401 |
| `INSUFFICIENT_SCOPE` | Token lacks required scopes | 403 |

## Complete Example

See the [MCP Server Example](../../apps/mcp-server-example) for a complete implementation including:

- Token validation with environment-based configuration
- Protected tool handlers with scope requirements
- RFC 9728 compliant error responses
- Graceful error handling

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  createTokenValidator,
  createWithAuth,
  AuthenticationError,
  AuthorizationError,
  createProtectedResourceMetadata,
  formatWwwAuthenticateHeader,
} from '@pingidentity/aic-mcp-sdk';

// Create validator
const validator = createTokenValidator({
  amUrl: process.env.AM_URL!,
  clientId: process.env.AM_CLIENT_ID!,
  clientSecret: process.env.AM_CLIENT_SECRET, // Optional
});

// Create auth wrapper
const withAuth = createWithAuth({ validator });

// Create server
const server = new McpServer({ name: 'my-server', version: '1.0.0' });

// Register protected tool
server.registerTool(
  'protected_action',
  {
    description: 'A protected action requiring authentication',
    inputSchema: { data: z.string() },
  },
  withAuth({ requiredScopes: ['action:execute'] }, async ({ data }, extra) => {
    const user = extra.authInfo?.extra?.sub;
    // ... perform action
    return { content: [{ type: 'text', text: `Done by ${user}` }] };
  })
);

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AM_URL` | Base URL of the AM instance | Yes |
| `AM_CLIENT_ID` | OAuth client ID | Yes |
| `AM_CLIENT_SECRET` | OAuth client secret | No* |
| `AM_REALM_PATH` | Realm path override | No |
| `AM_ACCESS_TOKEN` | Access token (for stdio transport) | No |

\* Required for opaque token introspection

## Requirements

- Node.js >= 20.0.0
- TypeScript >= 5.0 (for type definitions)

## Dependencies

- `jose` - JWT signing and verification
- `neverthrow` - Type-safe error handling
- `@modelcontextprotocol/sdk` (peer, optional) - MCP SDK types

## License

MIT
