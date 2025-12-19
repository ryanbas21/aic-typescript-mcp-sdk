# Token Acquisition Guide

This guide covers OAuth 2.0 token acquisition flows supported by the SDK.

## Table of Contents

- [Overview](#overview)
- [Authorization Code Flow](#authorization-code-flow)
- [Client Credentials Flow](#client-credentials-flow)
- [Token Refresh](#token-refresh)
- [Token Revocation](#token-revocation)
- [PKCE](#pkce)
- [Storage](#storage)

## Overview

The SDK supports three token acquisition methods:

| Flow | Use Case | Client Type |
|------|----------|-------------|
| Authorization Code + PKCE | User authentication | Public or Confidential |
| Client Credentials | Service-to-service | Confidential only |
| Token Refresh | Extending sessions | Both |

## Authorization Code Flow

The authorization code flow authenticates users via browser redirect.

### Step 1: Create Token Manager

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

### Step 2: Start Authorization

Generate the authorization URL and redirect the user:

```typescript
const result = await tokenManager.startAuthorization({
  additionalScopes: ['custom:scope'],  // Optional: request additional scopes
  resource: 'https://api.example.com', // Optional: RFC 8707 resource indicator
  loginHint: 'user@example.com',       // Optional: pre-fill username
  prompt: 'consent',                   // Optional: 'none' | 'login' | 'consent'
});

if ('url' in result) {
  // Redirect user to result.url
  // result.state contains the state parameter for CSRF protection
  console.log('Redirect to:', result.url);
}
```

### Step 3: Handle Callback

At your redirect URI, exchange the authorization code for tokens:

```typescript
// Extract code and state from callback URL
const url = new URL(request.url);
const code = url.searchParams.get('code');
const state = url.searchParams.get('state');

if (code && state) {
  const result = await tokenManager.handleCallback(code, state);

  if (result.success) {
    console.log('Access Token:', result.tokens.accessToken);
    console.log('Refresh Token:', result.tokens.refreshToken);
    console.log('Expires At:', new Date(result.tokens.expiresAt));
    console.log('ID Token:', result.tokens.idToken);
  } else {
    console.error('Error:', result.error.code, result.error.message);
  }
}
```

### Step 4: Get Access Token

Retrieve a valid access token, with automatic refresh if expired:

```typescript
const result = await tokenManager.getAccessToken();

if (result.success) {
  // Use result.accessToken for API calls
  const response = await fetch('https://api.example.com/data', {
    headers: {
      Authorization: `Bearer ${result.accessToken}`,
    },
  });
}
```

## Client Credentials Flow

For service-to-service authentication without user involvement.

**Requirements:** Confidential client (must have `clientSecret`)

```typescript
const tokenManager = createTokenManager({
  amUrl: 'https://your-tenant.forgeblocks.com',
  client: {
    clientType: 'confidential',
    clientId: 'my-service',
    clientSecret: 'service-secret',
    redirectUri: 'https://not-used.example.com', // Not used for client credentials
    scopes: ['service:read'],
  },
});

const result = await tokenManager.getServiceToken({
  scopes: ['service:read', 'service:write'],  // Optional: override default scopes
  resource: 'https://api.example.com',        // Optional: target resource
});

if (result.success) {
  console.log('Service Token:', result.tokens.accessToken);
}
```

## Token Refresh

Tokens are refreshed automatically when calling `getAccessToken()`. You can also manage tokens manually:

### Check Current Token Set

```typescript
const tokenSet = await tokenManager.getTokenSet();

if (tokenSet) {
  console.log('Has tokens');
  console.log('Expires at:', new Date(tokenSet.expiresAt));
  console.log('Has refresh token:', tokenSet.refreshToken !== undefined);
} else {
  console.log('No tokens stored');
}
```

### Manual Refresh

The `getAccessToken()` method handles refresh automatically:

```typescript
// This will refresh the token if it's about to expire
// (within the refresh buffer, default: 60 seconds)
const result = await tokenManager.getAccessToken();
```

## Token Revocation

Revoke the current access token:

```typescript
const result = await tokenManager.revokeToken();

if (result.success) {
  console.log('Token revoked');
} else {
  console.error('Revocation failed:', result.error.message);
}
```

Clear all stored tokens without revocation:

```typescript
await tokenManager.clearTokens();
```

## PKCE

The SDK automatically uses PKCE (Proof Key for Code Exchange) with S256 challenge method for all authorization code flows. This is required by the MCP specification.

### How PKCE Works

1. **Start authorization**: SDK generates a random `code_verifier` and computes `code_challenge = SHA256(code_verifier)`
2. **Authorization request**: `code_challenge` is sent to the authorization server
3. **Token exchange**: `code_verifier` is sent to prove possession

### Verify PKCE Support

Before starting the flow, you can verify the server supports PKCE:

```typescript
import { verifyPkceSupport, requirePkceSupport } from '@pingidentity/aic-mcp-sdk';

// Soft check (returns support info)
const support = verifyPkceSupport(discoveryDocument);
if (!support.supported) {
  console.warn('PKCE may not be supported:', support.warning);
}

// Hard requirement (returns Result)
const result = requirePkceSupport(discoveryDocument);
if (result.isErr()) {
  throw new Error(`PKCE not supported: ${result.error.message}`);
}
```

## Storage

Tokens and PKCE state are stored using the `SecureStorage` interface. The SDK provides an in-memory implementation by default.

### Default In-Memory Storage

```typescript
import { createMemoryStorage } from '@pingidentity/aic-mcp-sdk';

const storage = createMemoryStorage();

const tokenManager = createTokenManager(
  { amUrl, client },
  storage  // Pass as second argument
);
```

### Custom Storage

Implement the `SecureStorage` interface for persistent storage:

```typescript
interface SecureStorage {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
}

// Example: Redis-backed storage
const redisStorage: SecureStorage = {
  async get(key) {
    return await redis.get(key) ?? undefined;
  },
  async set(key, value, ttlMs) {
    if (ttlMs) {
      await redis.set(key, value, 'PX', ttlMs);
    } else {
      await redis.set(key, value);
    }
  },
  async delete(key) {
    const result = await redis.del(key);
    return result > 0;
  },
  async clear() {
    // Implementation depends on your key prefix strategy
  },
};

const tokenManager = createTokenManager(config, redisStorage);
```

## Error Handling

All token acquisition methods return discriminated union results:

```typescript
const result = await tokenManager.handleCallback(code, state);

if (result.success) {
  // TypeScript knows result.tokens exists
  console.log(result.tokens.accessToken);
} else {
  // TypeScript knows result.error exists
  console.error(result.error.code);    // 'invalid_grant', 'network_error', etc.
  console.error(result.error.message);
  console.error(result.error.cause);   // Original error if available
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `invalid_grant` | Authorization code is invalid or expired |
| `invalid_client` | Client authentication failed |
| `expired_token` | Token has expired and cannot be refreshed |
| `network_error` | Network request failed |
| `discovery_error` | Failed to fetch OIDC discovery document |
| `pkce_error` | PKCE validation failed |
| `state_mismatch` | State parameter doesn't match (possible CSRF) |
