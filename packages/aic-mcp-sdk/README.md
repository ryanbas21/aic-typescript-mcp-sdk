# @pingidentity/aic-mcp-sdk

Authentication SDK for MCP (Model Context Protocol) servers integrating with PingOne Advanced Identity Cloud (AIC).

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Token Validation](#token-validation)
  - [Protecting MCP Tools](#protecting-mcp-tools)
- [Guides](#guides)
- [API Reference](#api-reference)
  - [Token Validation](#api-token-validation)
  - [MCP Integration](#api-mcp-integration)
  - [Token Acquisition](#api-token-acquisition)
  - [Token Exchange](#api-token-exchange)
  - [Delegation Chain](#api-delegation-chain)
  - [Storage](#api-storage)
  - [Advanced APIs](#api-advanced)
- [Error Handling](#error-handling)
- [Environment Variables](#environment-variables)
- [Requirements](#requirements)

## Features

| Feature | Description |
|---------|-------------|
| **JWT Validation** | Verify RS256-signed JWTs using JWKS from OIDC discovery |
| **Token Introspection** | RFC 7662 introspection for opaque tokens |
| **Token Acquisition** | OAuth 2.1 flows with PKCE (authorization code, client credentials) |
| **Token Exchange** | RFC 8693 token exchange for identity delegation |
| **MCP Integration** | `withAuth` wrapper for protecting MCP tool handlers |
| **Delegation Chain** | Parse and validate `act` claims for agentic architectures |
| **RFC 9728** | Protected Resource Metadata for MCP-compliant 401 responses |

## Installation

```bash
npm install @pingidentity/aic-mcp-sdk
# or
pnpm add @pingidentity/aic-mcp-sdk
```

## Quick Start

### Token Validation

Validate an access token (JWT or opaque):

```typescript
import { createTokenValidator } from '@pingidentity/aic-mcp-sdk';

const validator = createTokenValidator({
  amUrl: 'https://your-tenant.forgeblocks.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret', // Required for opaque token introspection
});

const result = await validator.validate(accessToken);

if (result.valid) {
  console.log('Subject:', result.claims.sub);
  console.log('Scopes:', result.claims.scope);
} else {
  console.error('Error:', result.error, result.message);
}
```

### Protecting MCP Tools

Use `withAuth` to protect MCP tool handlers:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createTokenValidator, createWithAuth } from '@pingidentity/aic-mcp-sdk';

const validator = createTokenValidator({
  amUrl: process.env.AM_URL!,
  clientId: process.env.AM_CLIENT_ID!,
  clientSecret: process.env.AM_CLIENT_SECRET,
});

const withAuth = createWithAuth({ validator });

server.registerTool(
  'get_user_data',
  { description: 'Get user data', inputSchema: {} },
  withAuth({ requiredScopes: ['user:read'] }, async (args, extra) => {
    // extra.authInfo is guaranteed to exist here
    const userId = extra.authInfo.extra?.sub;
    return { content: [{ type: 'text', text: `User: ${userId}` }] };
  })
);
```

## Guides

| Guide | Description |
|-------|-------------|
| [Token Acquisition](./docs/token-acquisition.md) | OAuth 2.1 flows, PKCE, refresh tokens |
| [Delegation](./docs/delegation.md) | Agent-to-agent delegation with RFC 8693 |

---

## API Reference

### API: Token Validation

#### `createTokenValidator(config)`

Creates a token validator instance.

```typescript
import { createTokenValidator } from '@pingidentity/aic-mcp-sdk';

const validator = createTokenValidator({
  amUrl: 'https://your-tenant.forgeblocks.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret', // Optional, enables opaque token introspection
  realmPath: '/am/oauth2/realms/root/realms/alpha', // Optional
  discoveryCacheTtlMs: 3600000, // Optional, default: 1 hour
});
```

**Config Options:**

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `amUrl` | `string` | Yes | Base URL of the AIC instance |
| `clientId` | `string` | Yes | OAuth client ID |
| `clientSecret` | `string` | No | Client secret (required for introspection) |
| `realmPath` | `string` | No | Realm path (default: `/am/oauth2/realms/root/realms/alpha`) |
| `discoveryCacheTtlMs` | `number` | No | Discovery cache TTL in ms (default: 3600000) |

#### `validator.validate(token, options?)`

Validates an access token and returns a discriminated union result.

```typescript
const result = await validator.validate(token, {
  requiredScopes: ['openid', 'profile'],
  clockToleranceSeconds: 30,
});

if (result.valid) {
  // result.claims contains validated JWT claims
  console.log(result.claims.sub);
  console.log(result.claims.iss);
} else {
  // result.error contains error code
  console.log(result.error);   // 'EXPIRED_TOKEN', 'INVALID_SIGNATURE', etc.
  console.log(result.message);
}
```

**Validation Options:**

| Option | Type | Description |
|--------|------|-------------|
| `requiredScopes` | `string[]` | Scopes that must be present |
| `audience` | `string \| string[]` | Expected audience (default: clientId) |
| `clockToleranceSeconds` | `number` | Clock skew tolerance (default: 15) |

#### `validator.getAuthenticationInfo()`

Gets authorization server metadata for 401 responses.

```typescript
const info = await validator.getAuthenticationInfo();
// { authorizationEndpoint, tokenEndpoint, issuer, ... }
```

#### `validator.refreshCache()`

Forces a refresh of the cached OIDC discovery document and JWKS.

---

### API: MCP Integration

#### `createWithAuth(config)`

Creates a `withAuth` wrapper function for protecting MCP tool handlers.

```typescript
import { createWithAuth } from '@pingidentity/aic-mcp-sdk';

const withAuth = createWithAuth({
  validator,
  tokenExtractor: {
    envVar: 'AM_ACCESS_TOKEN',      // Environment variable name
    metaField: 'accessToken',        // Request _meta field name
    stdioTokenSource: 'both',        // 'env' | 'meta' | 'both'
  },
});

const handler = withAuth(
  { requiredScopes: ['read', 'write'] },
  async (args, extra) => {
    const { token, clientId, scopes, expiresAt, extra: claims } = extra.authInfo;
    return { content: [{ type: 'text', text: 'Success' }] };
  }
);
```

#### `AuthenticationError`

Thrown when authentication fails (HTTP 401).

```typescript
import { AuthenticationError } from '@pingidentity/aic-mcp-sdk';

try {
  await protectedHandler(args, extra);
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.log(error.code);              // 'MISSING_TOKEN', 'EXPIRED_TOKEN', etc.
    console.log(error.authenticationInfo); // For 401 response body
    console.log(error.httpStatusCode);     // 401
  }
}
```

#### `AuthorizationError`

Thrown when authorization fails due to insufficient scopes (HTTP 403).

```typescript
import { AuthorizationError } from '@pingidentity/aic-mcp-sdk';

if (error instanceof AuthorizationError) {
  console.log(error.requiredScopes);  // ['admin']
  console.log(error.presentScopes);   // ['read', 'write']
  console.log(error.missingScopes);   // ['admin']
  console.log(error.httpStatusCode);  // 403
}
```

#### `createProtectedResourceMetadata(config)`

Creates RFC 9728 Protected Resource Metadata.

```typescript
import { createProtectedResourceMetadata } from '@pingidentity/aic-mcp-sdk';

const metadata = createProtectedResourceMetadata({
  resourceUrl: 'https://mcp.example.com',
  authorizationServers: 'https://auth.example.com/oauth2',
  scopesSupported: ['openid', 'profile', 'read'],
  resourceName: 'My MCP Server',
});
```

#### `formatWwwAuthenticateHeader(options)`

Formats a WWW-Authenticate header for 401 responses.

```typescript
import { formatWwwAuthenticateHeader } from '@pingidentity/aic-mcp-sdk';

const header = formatWwwAuthenticateHeader({
  resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
  error: 'invalid_token',
  errorDescription: 'Token has expired',
});
// => 'Bearer resource_metadata="https://...", error="invalid_token", ...'
```

---

### API: Token Acquisition

#### `createTokenManager(config)`

Creates a high-level token manager for OAuth flows.

```typescript
import { createTokenManager } from '@pingidentity/aic-mcp-sdk';

const tokenManager = createTokenManager({
  amUrl: 'https://your-tenant.forgeblocks.com',
  realmPath: '/am/oauth2/realms/root/realms/alpha',
  client: {
    clientType: 'confidential',
    clientId: 'my-mcp-server',
    clientSecret: 'my-secret',
    redirectUri: 'https://mcp.example.com/callback',
    scopes: ['openid', 'profile'],
  },
});
```

**Client Configuration:**

```typescript
// Public client (browser apps, native apps)
interface PublicClientConfig {
  clientType: 'public';
  clientId: string;
  redirectUri: string;
  scopes: readonly string[];
}

// Confidential client (server apps)
interface ConfidentialClientConfig {
  clientType: 'confidential';
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: readonly string[];
}
```

#### Token Manager Methods

| Method | Description |
|--------|-------------|
| `startAuthorization(options?)` | Start authorization code flow with PKCE |
| `handleCallback(code, state)` | Exchange authorization code for tokens |
| `getAccessToken()` | Get valid access token (auto-refreshes if needed) |
| `getTokenSet()` | Get current token set without refresh |
| `getServiceToken(options?)` | Get token via client credentials (confidential only) |
| `exchangeToken(request)` | Exchange token via RFC 8693 (confidential only) |
| `revokeToken()` | Revoke current access token |
| `clearTokens()` | Clear all stored tokens |

**Authorization Code Flow:**

```typescript
// 1. Start authorization (returns URL for browser redirect)
const result = await tokenManager.startAuthorization({
  additionalScopes: ['custom:scope'],
  resource: 'https://api.example.com',
});

if ('url' in result) {
  // Redirect user to result.url
}

// 2. Handle callback at your redirect URI
const tokenResult = await tokenManager.handleCallback(code, state);

if (tokenResult.success) {
  console.log('Access token:', tokenResult.tokens.accessToken);
}

// 3. Later: get valid access token (auto-refreshes)
const accessResult = await tokenManager.getAccessToken();

if (accessResult.success) {
  console.log('Token:', accessResult.accessToken);
}
```

**Client Credentials Flow:**

```typescript
const result = await tokenManager.getServiceToken({
  scopes: ['service:read'],
  resource: 'https://api.example.com',
});

if (result.success) {
  console.log('Service token:', result.tokens.accessToken);
}
```

---

### API: Token Exchange

RFC 8693 token exchange for identity delegation.

```typescript
const result = await tokenManager.exchangeToken({
  subjectToken: userAccessToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  audience: 'https://downstream-api.example.com',
  scope: 'read write',
});

if (result.success) {
  console.log('Exchanged token:', result.tokens.accessToken);
  console.log('Token type:', result.issuedTokenType);
}
```

**Token Exchange Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subjectToken` | `string` | Yes | Token to exchange |
| `subjectTokenType` | `string` | Yes | Subject token type URI |
| `audience` | `string` | No | Target audience |
| `scope` | `string` | No | Requested scopes |
| `resource` | `string` | No | Target resource |
| `actorToken` | `string` | No | Actor token for delegation |
| `actorTokenType` | `string` | No | Actor token type URI |

**Token Type URIs:**

```typescript
// Standard OAuth token types
'urn:ietf:params:oauth:token-type:access_token'
'urn:ietf:params:oauth:token-type:refresh_token'
'urn:ietf:params:oauth:token-type:id_token'
'urn:ietf:params:oauth:token-type:jwt'
```

---

### API: Delegation Chain

Utilities for working with RFC 8693 actor (`act`) claims.

#### `isDelegatedToken(claims)`

Checks if a token has delegation (contains `act` claim).

```typescript
import { isDelegatedToken } from '@pingidentity/aic-mcp-sdk';

if (isDelegatedToken(claims)) {
  console.log('Token was obtained through delegation');
}
```

#### `getDelegationContext(claims)`

Extracts full delegation context from token claims.

```typescript
import { getDelegationContext } from '@pingidentity/aic-mcp-sdk';

const context = getDelegationContext(claims);

console.log(context.subject);        // 'user@example.com'
console.log(context.isDelegated);    // true
console.log(context.depth);          // 2
console.log(context.immediateActor); // { sub: 'https://mcp-server.example.com' }
console.log(context.chain);          // [{ sub: '...' }, { sub: '...' }]
```

**DelegationContext:**

| Field | Type | Description |
|-------|------|-------------|
| `subject` | `string` | Original subject (end user) |
| `isDelegated` | `boolean` | Whether token has delegation |
| `depth` | `number` | Delegation chain depth (0 = no delegation) |
| `immediateActor` | `DelegationActor \| undefined` | Direct caller |
| `chain` | `DelegationActor[]` | Full actor chain |

#### `validateDelegationChain(claims, options)`

Validates delegation chain against policy constraints.

```typescript
import { validateDelegationChain } from '@pingidentity/aic-mcp-sdk';

const result = validateDelegationChain(claims, {
  maxDepth: 3,
  requireDelegation: true,
  requiredActors: ['https://trusted-agent.example.com'],
  forbiddenActors: ['https://blocked-service.example.com'],
});

if (!result.valid) {
  console.error('Policy violations:', result.errors);
}
```

**Validation Options:**

| Option | Type | Description |
|--------|------|-------------|
| `maxDepth` | `number` | Maximum allowed delegation depth |
| `requireDelegation` | `boolean` | Token must have `act` claim |
| `requiredActors` | `string[]` | Actors that must be in the chain |
| `forbiddenActors` | `string[]` | Actors that must NOT be in the chain |

---

### API: Storage

#### `createMemoryStorage()`

Creates in-memory storage for tokens and state.

```typescript
import { createMemoryStorage } from '@pingidentity/aic-mcp-sdk';

const storage = createMemoryStorage();

await storage.set('key', 'value', 3600000); // Optional TTL in ms
const value = await storage.get('key');
await storage.delete('key');
await storage.clear();
```

**SecureStorage Interface:**

```typescript
interface SecureStorage {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
}
```

---

### API: Advanced

These APIs are for advanced use cases requiring custom implementations.

#### `createFetchClient(options?)`

Creates a custom HTTP client.

```typescript
import { createFetchClient } from '@pingidentity/aic-mcp-sdk';

const httpClient = createFetchClient({
  timeout: 10000,
});
```

#### `createMemoryCache(ttlMs)`

Creates a memory cache with TTL.

```typescript
import { createMemoryCache } from '@pingidentity/aic-mcp-sdk';

const cache = createMemoryCache(3600000); // 1 hour TTL
```

#### `createCachedDiscoveryFetcher(options)`

Creates a cached OIDC discovery document fetcher.

```typescript
import { createCachedDiscoveryFetcher } from '@pingidentity/aic-mcp-sdk';

const fetcher = createCachedDiscoveryFetcher({
  amUrl: 'https://your-tenant.forgeblocks.com',
  realmPath: '/am/oauth2/realms/root/realms/alpha',
});
```

#### `verifyPkceSupport(discovery)` / `requirePkceSupport(discovery)`

Verify PKCE S256 support per MCP spec.

```typescript
import { verifyPkceSupport, requirePkceSupport } from '@pingidentity/aic-mcp-sdk';

const support = verifyPkceSupport(discoveryDocument);
if (!support.supported) {
  console.warn(support.warning);
}

// Or require it (returns Result)
const result = requirePkceSupport(discoveryDocument);
if (result.isErr()) {
  throw new Error(result.error.message);
}
```

#### `buildClientMetadataDocument(options)` / `fetchClientMetadataDocument(url)`

Build or fetch MCP Client ID Metadata Documents.

```typescript
import { buildClientMetadataDocument, fetchClientMetadataDocument } from '@pingidentity/aic-mcp-sdk';

// Build metadata
const metadata = buildClientMetadataDocument({
  clientId: 'https://mcp.example.com/client.json',
  clientName: 'My MCP Client',
  redirectUris: ['https://mcp.example.com/callback'],
});

// Fetch from URL
const result = await fetchClientMetadataDocument({
  clientIdUrl: 'https://mcp.example.com/client.json',
});
```

---

## Error Handling

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `MISSING_TOKEN` | No token provided | 401 |
| `MALFORMED_TOKEN` | Invalid token format | 401 |
| `EXPIRED_TOKEN` | Token has expired | 401 |
| `INVALID_SIGNATURE` | JWT signature verification failed | 401 |
| `INVALID_ISSUER` | Token issuer mismatch | 401 |
| `INVALID_AUDIENCE` | Token audience mismatch | 401 |
| `REVOKED_TOKEN` | Token has been revoked | 401 |
| `INSUFFICIENT_SCOPE` | Missing required scopes | 403 |

### Token Validation Flow

```
1. Check token exists          → MISSING_TOKEN if empty
2. Detect format               → JWT (3 parts) or opaque
3. For JWTs:
   a. Fetch OIDC discovery     → Cached 1 hour
   b. Verify signature (JWKS)  → INVALID_SIGNATURE on failure
   c. Validate claims          → EXPIRED_TOKEN, INVALID_ISSUER, etc.
   d. Check scopes             → INSUFFICIENT_SCOPE if missing
4. For opaque tokens:
   a. Call introspection       → Requires clientSecret
   b. Check active status      → REVOKED_TOKEN if inactive
   c. Check scopes             → INSUFFICIENT_SCOPE if missing
```

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AM_URL` | Base URL of the AIC instance | Yes |
| `AM_CLIENT_ID` | OAuth client ID | Yes |
| `AM_CLIENT_SECRET` | OAuth client secret | No* |
| `AM_REALM_PATH` | Realm path override | No |
| `AM_ACCESS_TOKEN` | Access token (stdio transport) | No |

\* Required for opaque token introspection and confidential client flows

---

## Requirements

- Node.js >= 20.0.0
- TypeScript >= 5.0 (for type definitions)

## Dependencies

- `jose` - JWT signing and verification
- `neverthrow` - Type-safe error handling

## License

MIT
