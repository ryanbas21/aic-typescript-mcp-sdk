# MCP Agent Delegation Demo

Demonstrates agent-to-agent identity delegation using RFC 8693 token exchange with PingOne Advanced Identity Cloud.

## Overview

This MCP server shows how to:

1. Receive a user token from an MCP client (e.g., Claude Desktop)
2. Validate the incoming token
3. Exchange the token for a downstream API using RFC 8693
4. Preserve the delegation chain (`act` claims)
5. Validate delegation policies

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌────────────────┐
│    User     │────▶│  MCP Client │────▶│  This Server     │────▶│ Downstream API │
│             │     │  (Claude)   │     │                  │     │                │
└─────────────┘     └─────────────┘     └──────────────────┘     └────────────────┘
       │                   │                     │
       │ 1. Authenticate   │                     │
       │──────────────────▶│                     │
       │                   │ 2. User token       │
       │                   │────────────────────▶│
       │                   │                     │ 3. Token exchange
       │                   │                     │    (RFC 8693)
       │                   │                     │
       │                   │                     │ Result: Delegated token
       │                   │                     │ with `act` claim showing
       │                   │                     │ this server acted on
       │                   │                     │ behalf of the user
```

## Prerequisites

- Node.js >= 20.0.0
- PingOne AIC tenant with:
  - OAuth client configured for this MCP server (confidential)
  - Token exchange enabled
  - Downstream API audience registered

## Setup

### 1. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# PingOne AIC Configuration
AM_URL=https://your-tenant.forgeblocks.com
AM_REALM_PATH=/am/oauth2/realms/root/realms/alpha

# This MCP Server's OAuth Client (confidential)
AM_CLIENT_ID=your-mcp-server-client-id
AM_CLIENT_SECRET=your-mcp-server-client-secret

# Downstream API Configuration
DOWNSTREAM_API_AUDIENCE=https://api.example.com
DOWNSTREAM_API_SCOPES=read write
```

### 2. Build

```bash
pnpm build
```

### 3. Run with MCP Inspector

```bash
npx @anthropic/mcp-inspector node dist/index.js
```

## Tools

| Tool | Description |
|------|-------------|
| `inspect_delegation` | View the delegation chain of your current token |
| `exchange_for_downstream` | Exchange token for downstream API access |
| `validate_chain` | Validate delegation against security policies |
| `call_downstream_api` | Simulate calling downstream with delegated token |
| `is_delegated` | Check if token has `act` claim |

## Usage Examples

### Inspect Delegation Chain

See who the original user is and which agents have acted on their behalf:

```json
{
  "name": "inspect_delegation"
}
```

Response:
```json
{
  "message": "This is a delegated token with an actor chain",
  "delegation": {
    "originalUser": "user@example.com",
    "isDelegated": true,
    "delegationDepth": 1,
    "immediateActor": { "sub": "claude-desktop" },
    "fullActorChain": [{ "sub": "claude-desktop" }]
  }
}
```

### Exchange Token for Downstream

Exchange your token to call a downstream API:

```json
{
  "name": "exchange_for_downstream",
  "arguments": {
    "customScopes": ["read"]
  }
}
```

Response shows the new token and updated delegation chain.

### Validate Delegation Policies

Validate the chain against security requirements:

```json
{
  "name": "validate_chain",
  "arguments": {
    "maxDepth": 3,
    "requiredActors": ["https://trusted-service.example.com"],
    "forbiddenActors": ["https://blocked-service.example.com"]
  }
}
```

## Programmatic Usage

You can also use this server as a library:

```typescript
import { createServer, createDelegationServerConfig } from '@pingidentity/mcp-agent-delegation';

// Create configuration (env vars or programmatic)
const config = createDelegationServerConfig({
  amUrl: 'https://your-tenant.forgeblocks.com',
  clientId: 'my-mcp-server',
  clientSecret: 'secret',
  downstreamAudience: 'https://api.example.com',
});

// Create and connect server
const server = createServer(config);
const transport = new StdioServerTransport();
await server.connect(transport);
```

## Configuration Options

### DelegationServerConfig

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `amUrl` | `string` | Yes | PingOne AIC base URL |
| `realmPath` | `string` | No | OAuth realm path |
| `client.clientId` | `string` | Yes | This server's client ID |
| `client.clientSecret` | `string` | Yes | This server's client secret |
| `downstreamAudience` | `string` | Yes | Target API for token exchange |
| `downstreamScopes` | `string[]` | No | Scopes to request |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AM_URL` | PingOne AIC base URL |
| `AM_REALM_PATH` | OAuth realm path |
| `AM_CLIENT_ID` | This server's OAuth client ID |
| `AM_CLIENT_SECRET` | This server's OAuth client secret |
| `DOWNSTREAM_API_AUDIENCE` | Target API audience |
| `DOWNSTREAM_API_SCOPES` | Space-separated scopes |

## Understanding the Delegation Flow

### Before Token Exchange

User's token (from MCP client):
```json
{
  "sub": "user@example.com",
  "aud": "mcp-client",
  "iss": "https://auth.example.com"
}
```

### After Token Exchange

Delegated token (for downstream API):
```json
{
  "sub": "user@example.com",
  "aud": "downstream-api",
  "iss": "https://auth.example.com",
  "act": {
    "sub": "this-mcp-server-client-id"
  }
}
```

The `act` claim shows this MCP server is acting on behalf of the user.

### Nested Delegation

If the MCP client already delegated:
```json
{
  "sub": "user@example.com",
  "act": {
    "sub": "this-mcp-server",
    "act": {
      "sub": "claude-desktop"
    }
  }
}
```

Shows: `User → Claude Desktop → This Server`

## Security Considerations

1. **Validate delegation depth** - Use `maxDepth` to prevent unbounded chains
2. **Require trusted actors** - Use `requiredActors` for known services
3. **Block bad actors** - Use `forbiddenActors` for compromised services
4. **Minimize scopes** - Only request scopes needed for downstream calls
5. **Audit logging** - Log delegation chains for compliance

## Development

```bash
# Development mode
pnpm dev

# Build
pnpm build

# Type check
pnpm typecheck
```

## See Also

- [SDK Documentation](../../packages/aic-mcp-sdk/README.md)
- [Delegation Guide](../../packages/aic-mcp-sdk/docs/delegation.md)
- [RFC 8693 - Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
