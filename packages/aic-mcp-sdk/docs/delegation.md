# Agent-to-Agent Delegation Guide

This guide covers identity delegation for agentic architectures using RFC 8693 token exchange.

## Table of Contents

- [Overview](#overview)
- [The Actor Claim](#the-actor-claim)
- [Token Exchange](#token-exchange)
- [Delegation Chain Utilities](#delegation-chain-utilities)
- [Validation Policies](#validation-policies)
- [Security Considerations](#security-considerations)
- [Complete Example](#complete-example)

## Overview

In agentic architectures, AI agents often need to call downstream services on behalf of users. Identity delegation preserves the original user's identity while recording which agents acted on their behalf.

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌────────────────┐
│    User     │────▶│  MCP Client │────▶│  MCP Server      │────▶│ Downstream API │
│             │     │  (Claude)   │     │  (your app)      │     │                │
└─────────────┘     └─────────────┘     └──────────────────┘     └────────────────┘
       │                   │                     │                       │
       │ 1. Authenticate   │                     │                       │
       │──────────────────▶│                     │                       │
       │                   │ 2. User token       │                       │
       │                   │────────────────────▶│                       │
       │                   │                     │ 3. Token exchange     │
       │                   │                     │──────────────────────▶│
       │                   │                     │    (RFC 8693)         │
       │                   │                     │                       │
       │                   │                     │ 4. Delegated token    │
       │                   │                     │    with `act` claim   │
       │                   │                     │◀──────────────────────│
```

## The Actor Claim

RFC 8693 defines the `act` (actor) claim to represent delegation chains. When a service exchanges a token, the authorization server adds an `act` claim identifying the service.

### Before Exchange (User Token)

```json
{
  "sub": "user@example.com",
  "aud": "mcp-client",
  "iss": "https://auth.example.com",
  "exp": 1735689600
}
```

### After Exchange (Delegated Token)

```json
{
  "sub": "user@example.com",
  "aud": "downstream-api",
  "iss": "https://auth.example.com",
  "exp": 1735689600,
  "act": {
    "sub": "mcp-server-client-id"
  }
}
```

### Nested Delegation

When multiple agents are involved, `act` claims nest:

```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "downstream-mcp-server",
    "act": {
      "sub": "upstream-mcp-server",
      "act": {
        "sub": "claude-desktop"
      }
    }
  }
}
```

This shows: `User → Claude Desktop → Upstream MCP → Downstream MCP`

## Token Exchange

Use the token manager to exchange tokens for downstream API access.

### Basic Exchange

```typescript
import { createTokenManager } from '@pingidentity/aic-mcp-sdk';

const tokenManager = createTokenManager({
  amUrl: 'https://your-tenant.forgeblocks.com',
  client: {
    clientType: 'confidential',
    clientId: 'my-mcp-server',
    clientSecret: 'my-secret',
    redirectUri: 'https://mcp.example.com/callback',
    scopes: ['openid'],
  },
});

// Exchange user's token for downstream API
const result = await tokenManager.exchangeToken({
  subjectToken: userAccessToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  audience: 'https://downstream-api.example.com',
  scope: 'read write',
});

if (result.success) {
  // Use exchanged token for downstream call
  const response = await fetch('https://downstream-api.example.com/data', {
    headers: {
      Authorization: `Bearer ${result.tokens.accessToken}`,
    },
  });
}
```

### Exchange Request Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subjectToken` | `string` | Yes | The token to exchange |
| `subjectTokenType` | `string` | Yes | Token type URI |
| `audience` | `string` | No | Target service identifier |
| `scope` | `string` | No | Space-separated scopes |
| `resource` | `string` | No | Target resource URI |
| `actorToken` | `string` | No | Actor token for impersonation |
| `actorTokenType` | `string` | No | Actor token type URI |

### Token Type URIs

```typescript
// Standard OAuth token types
'urn:ietf:params:oauth:token-type:access_token'  // Most common
'urn:ietf:params:oauth:token-type:refresh_token'
'urn:ietf:params:oauth:token-type:id_token'
'urn:ietf:params:oauth:token-type:jwt'
```

## Delegation Chain Utilities

The SDK provides utilities for working with delegation chains.

### Check if Token is Delegated

```typescript
import { isDelegatedToken } from '@pingidentity/aic-mcp-sdk';

if (isDelegatedToken(claims)) {
  console.log('This token has an act claim');
}
```

### Get Delegation Context

```typescript
import { getDelegationContext } from '@pingidentity/aic-mcp-sdk';

const context = getDelegationContext(claims);

console.log('Original user:', context.subject);
console.log('Is delegated:', context.isDelegated);
console.log('Chain depth:', context.depth);
console.log('Direct caller:', context.immediateActor?.sub);
console.log('Full chain:', context.chain.map(a => a.sub));
```

**DelegationContext Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `subject` | `string` | Original user (from `sub` claim) |
| `isDelegated` | `boolean` | `true` if `act` claim exists |
| `depth` | `number` | Number of actors in chain (0 = no delegation) |
| `immediateActor` | `DelegationActor \| undefined` | Most recent actor |
| `chain` | `DelegationActor[]` | All actors, immediate first |

## Validation Policies

Validate delegation chains against security policies.

### Basic Validation

```typescript
import { validateDelegationChain } from '@pingidentity/aic-mcp-sdk';

const result = validateDelegationChain(claims, {
  maxDepth: 3,
});

if (!result.valid) {
  console.error('Validation failed:', result.errors);
}
```

### Policy Options

| Option | Type | Description |
|--------|------|-------------|
| `maxDepth` | `number` | Maximum allowed delegation hops |
| `requireDelegation` | `boolean` | Token MUST have `act` claim |
| `requiredActors` | `string[]` | Actors that MUST be in chain |
| `forbiddenActors` | `string[]` | Actors that must NOT be in chain |

### Examples

**Limit Delegation Depth:**

```typescript
const result = validateDelegationChain(claims, {
  maxDepth: 2,  // User → Agent1 → Agent2 is OK, but not deeper
});
```

**Require Trusted Gateway:**

```typescript
const result = validateDelegationChain(claims, {
  requiredActors: ['https://api-gateway.example.com'],
});
```

**Block Untrusted Services:**

```typescript
const result = validateDelegationChain(claims, {
  forbiddenActors: [
    'https://deprecated-service.example.com',
    'https://untrusted.example.com',
  ],
});
```

**Require Delegation:**

```typescript
const result = validateDelegationChain(claims, {
  requireDelegation: true,  // Direct user tokens not allowed
});
```

**Combined Policies:**

```typescript
const result = validateDelegationChain(claims, {
  maxDepth: 5,
  requiredActors: ['https://api-gateway.example.com'],
  forbiddenActors: ['https://blocked.example.com'],
});

if (!result.valid) {
  // result.errors contains all violations
  for (const error of result.errors) {
    console.error(error);
  }
}
```

## Security Considerations

### 1. Limit Delegation Depth

Unbounded delegation chains can be exploited. Always set a reasonable `maxDepth`:

```typescript
validateDelegationChain(claims, { maxDepth: 5 });
```

### 2. Validate Actor Identity

Use `requiredActors` to ensure tokens passed through trusted services:

```typescript
validateDelegationChain(claims, {
  requiredActors: ['https://trusted-gateway.example.com'],
});
```

### 3. Block Known Bad Actors

Use `forbiddenActors` to reject tokens from compromised or deprecated services:

```typescript
validateDelegationChain(claims, {
  forbiddenActors: ['https://compromised-service.example.com'],
});
```

### 4. Audit Delegation Chains

Log delegation chains for security auditing:

```typescript
const context = getDelegationContext(claims);

console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  user: context.subject,
  delegationChain: context.chain.map(a => a.sub),
  depth: context.depth,
}));
```

### 5. Scope Reduction

Each delegation hop should request minimal required scopes:

```typescript
// User token has: openid, profile, read, write, admin
// MCP server only needs: read
const result = await tokenManager.exchangeToken({
  subjectToken: userToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  audience: 'downstream-api',
  scope: 'read',  // Only request what's needed
});
```

## Complete Example

Here's a complete MCP server implementing delegation:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  createTokenValidator,
  createTokenManager,
  createWithAuth,
  getDelegationContext,
  validateDelegationChain,
  AuthenticationError,
  AuthorizationError,
} from '@pingidentity/aic-mcp-sdk';

// Configuration
const config = {
  amUrl: process.env.AM_URL!,
  clientId: process.env.AM_CLIENT_ID!,
  clientSecret: process.env.AM_CLIENT_SECRET!,
  downstreamAudience: 'https://api.example.com',
};

// Create validator and token manager
const validator = createTokenValidator({
  amUrl: config.amUrl,
  clientId: config.clientId,
  clientSecret: config.clientSecret,
});

const tokenManager = createTokenManager({
  amUrl: config.amUrl,
  client: {
    clientType: 'confidential',
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: 'https://mcp.example.com/callback',
    scopes: ['openid'],
  },
});

const withAuth = createWithAuth({ validator });

// Create MCP server
const server = new McpServer({ name: 'delegation-demo', version: '1.0.0' });

// Tool that calls downstream API with delegation
server.registerTool(
  'call_api',
  {
    description: 'Call downstream API with delegated identity',
    inputSchema: { endpoint: { type: 'string' } },
  },
  withAuth({ requiredScopes: ['openid'] }, async ({ endpoint }, extra) => {
    const userToken = extra.authInfo.token;
    const claims = extra.authInfo.extra as Record<string, unknown>;

    // Validate delegation policy
    const validation = validateDelegationChain(claims, {
      maxDepth: 5,
      forbiddenActors: ['https://blocked.example.com'],
    });

    if (!validation.valid) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: 'Policy violation', details: validation.errors }),
        }],
        isError: true,
      };
    }

    // Exchange token for downstream API
    const exchangeResult = await tokenManager.exchangeToken({
      subjectToken: userToken,
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      audience: config.downstreamAudience,
      scope: 'read',
    });

    if (!exchangeResult.success) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: 'Token exchange failed', details: exchangeResult.error }),
        }],
        isError: true,
      };
    }

    // Call downstream API
    const response = await fetch(`${config.downstreamAudience}${endpoint}`, {
      headers: {
        Authorization: `Bearer ${exchangeResult.tokens.accessToken}`,
      },
    });

    const data = await response.json();

    // Log delegation for audit
    const context = getDelegationContext(claims);
    console.log('API call:', {
      user: context.subject,
      chain: context.chain.map(a => a.sub),
      endpoint,
    });

    return {
      content: [{ type: 'text', text: JSON.stringify(data) }],
    };
  })
);
```

## See Also

- [Token Acquisition Guide](./token-acquisition.md) - OAuth flows and PKCE
- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) - OAuth 2.0 Token Exchange
- [MCP Agent Delegation Example](../../../apps/mcp-agent-delegation) - Complete demo app
