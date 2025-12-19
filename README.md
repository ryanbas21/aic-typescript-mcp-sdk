# PingOne Advanced Identity Cloud SDK for AI Agents

Authentication and authorization SDK for AI agents and MCP (Model Context Protocol) servers integrating with PingOne Advanced Identity Cloud (AIC).

## Overview

This monorepo provides tools for building secure AI agents that authenticate users and delegate identity across service boundaries using OAuth 2.0 and RFC 8693 token exchange.

## Packages

| Package | Description |
|---------|-------------|
| [@pingidentity/aic-mcp-sdk](./packages/aic-mcp-sdk) | Core SDK for token validation, acquisition, and MCP integration |

## Example Applications

| App | Description |
|-----|-------------|
| [mcp-server-example](./apps/mcp-server-example) | Simple MCP server with OAuth authentication |
| [mcp-agent-delegation](./apps/mcp-agent-delegation) | Agent-to-agent delegation demo using RFC 8693 token exchange |

## Quick Start

### Installation

```bash
npm install @pingidentity/aic-mcp-sdk
# or
pnpm add @pingidentity/aic-mcp-sdk
```

### Protect an MCP Tool

```typescript
import { createTokenValidator, createWithAuth } from '@pingidentity/aic-mcp-sdk';

// Create validator
const validator = createTokenValidator({
  amUrl: 'https://your-tenant.forgeblocks.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});

// Create auth wrapper
const withAuth = createWithAuth({ validator });

// Protect a tool handler
server.registerTool(
  'protected_tool',
  { description: 'A protected tool', inputSchema: {} },
  withAuth({ requiredScopes: ['read'] }, async (args, extra) => {
    const userId = extra.authInfo?.extra?.sub;
    return { content: [{ type: 'text', text: `Hello ${userId}` }] };
  })
);
```

## Key Features

- **Token Validation** - JWT verification via JWKS, opaque token introspection (RFC 7662)
- **Token Acquisition** - OAuth 2.1 authorization code flow with PKCE
- **Token Exchange** - RFC 8693 for agent-to-agent delegation
- **MCP Integration** - `withAuth` wrapper for protecting MCP tools
- **Delegation Chain** - Utilities for parsing and validating `act` claims

## Documentation

- [SDK Documentation](./packages/aic-mcp-sdk/README.md) - Full API reference
- [Token Acquisition Guide](./packages/aic-mcp-sdk/docs/token-acquisition.md) - OAuth flows
- [Delegation Guide](./packages/aic-mcp-sdk/docs/delegation.md) - Agent-to-agent delegation

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌────────────────┐
│    User     │────▶│  MCP Client │────▶│  MCP Server      │────▶│ Downstream API │
│             │     │  (Claude)   │     │  (your app)      │     │                │
└─────────────┘     └─────────────┘     └──────────────────┘     └────────────────┘
       │                                        │
       │                                        │ Token Exchange
       ▼                                        ▼ (RFC 8693)
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PingOne Advanced Identity Cloud                              │
│                                                                                  │
│  • OAuth 2.0 / OIDC    • Token Exchange    • JWKS    • Token Introspection      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Type check
pnpm typecheck

# Lint
pnpm lint
```

## Requirements

- Node.js >= 20.0.0
- TypeScript >= 5.0

## License

MIT
