# MCP Server Example

A simple MCP server demonstrating OAuth authentication with PingOne Advanced Identity Cloud.

## Features

- Token validation on protected tool calls
- 401 responses with authorization URL for unauthenticated users
- User authentication flow (authorization code + PKCE)
- Example todos API integration (JSONPlaceholder)

## Prerequisites

- Node.js >= 20.0.0
- PingOne AIC tenant with OAuth client configured
- MCP client (e.g., Claude Desktop)

## Setup

### 1. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your PingOne AIC settings:

```bash
# Required
AM_URL=https://your-tenant.forgeblocks.com
AM_CLIENT_ID=your-client-id
AM_CLIENT_SECRET=your-client-secret

# Optional
AM_REALM_PATH=/am/oauth2/realms/root/realms/alpha
```

### 2. Build

```bash
pnpm build
```

### 3. Run with MCP Inspector

```bash
npx @anthropic/mcp-inspector node dist/index.js
```

Or run directly:

```bash
node dist/index.js
```

## Tools

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `auth_start` | Start OAuth login flow | No |
| `auth_callback` | Complete OAuth login | No |
| `auth_status` | Check authentication status | No |
| `auth_logout` | Log out current user | No |
| `list_todos` | List todos from API | Yes |
| `get_todo` | Get a specific todo | Yes |
| `get_todos_summary` | Get todos statistics | Yes |

## Usage Flow

### 1. Start Authentication

Call `auth_start` to get an authorization URL:

```json
{
  "name": "auth_start"
}
```

Response includes the URL to open in a browser.

### 2. Complete Authentication

After authorizing in the browser, call `auth_callback` with the code:

```json
{
  "name": "auth_callback",
  "arguments": {
    "code": "authorization-code-from-callback",
    "state": "state-from-callback"
  }
}
```

### 3. Use Protected Tools

Now you can call protected tools:

```json
{
  "name": "list_todos",
  "arguments": {
    "userId": 1
  }
}
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AM_URL` | Yes | PingOne AIC base URL |
| `AM_CLIENT_ID` | Yes | OAuth client ID |
| `AM_CLIENT_SECRET` | Yes | OAuth client secret |
| `AM_REALM_PATH` | No | OAuth realm path |

### OAuth Client Requirements

Configure your OAuth client in PingOne AIC with:

- **Grant Types**: Authorization Code
- **Response Types**: code
- **Redirect URI**: `http://localhost:3000/callback` (or your configured URI)
- **PKCE**: Required (S256)
- **Scopes**: openid, profile (and any additional scopes needed)

## Development

```bash
# Run in development mode (with hot reload)
pnpm dev

# Build
pnpm build

# Type check
pnpm typecheck
```

## Architecture

```
src/
├── index.ts    # Main server with tool registrations
├── config.ts   # Configuration loading
└── auth.ts     # Authentication manager
```

The server uses:
- `@pingidentity/aic-mcp-sdk` for token validation and OAuth flows
- `@modelcontextprotocol/sdk` for MCP server implementation
- JSONPlaceholder API for demo data

## See Also

- [SDK Documentation](../../packages/aic-mcp-sdk/README.md)
- [Delegation Example](../mcp-agent-delegation/README.md)
