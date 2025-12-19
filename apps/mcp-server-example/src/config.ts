/**
 * MCP Server Configuration Module
 *
 * @packageDocumentation
 */

import type { PublicClientConfig, TokenManagerConfig } from '@pingidentity/aic-mcp-sdk';

/**
 * MCP Server OAuth Configuration.
 * Uses a public client for user authentication (authorization code + PKCE).
 */
export interface McpServerConfig {
  /** PingOne Advanced Identity Cloud URL */
  readonly amUrl: string;
  /** OAuth realm path */
  readonly realmPath: string;
  /** Public client configuration for user auth */
  readonly client: PublicClientConfig;
  /** Scopes required from users to access protected tools */
  readonly requiredUserScopes: readonly string[];
}

/**
 * Creates the MCP server configuration from environment variables.
 *
 * Required env vars:
 * - AM_URL: PingOne AIC URL
 * - AM_CLIENT_ID: Public client ID (e.g., "mcp_test")
 *
 * Optional env vars:
 * - AM_REALM_PATH: OAuth realm path (default: /am/oauth2/realms/root/realms/alpha)
 * - MCP_SERVER_URL: Server URL for redirect (default: http://127.0.0.1:3000)
 * - OAUTH_REDIRECT_URI: Override redirect URI
 */
export function createServerConfig(): McpServerConfig {
  const amUrl = process.env['AM_URL'];
  const clientId = process.env['AM_CLIENT_ID'];
  const realmPath = process.env['AM_REALM_PATH'] ?? '/am/oauth2/realms/root/realms/alpha';
  const serverUrl = process.env['MCP_SERVER_URL'] ?? 'http://127.0.0.1:3000';
  const redirectUri = process.env['OAUTH_REDIRECT_URI'] ?? `${serverUrl}/oauth/callback`;

  if (amUrl === undefined || amUrl.length === 0) {
    throw new Error('AM_URL is required');
  }

  if (clientId === undefined || clientId.length === 0) {
    throw new Error('AM_CLIENT_ID is required');
  }

  return {
    amUrl,
    realmPath,
    client: {
      clientType: 'public',
      clientId,
      redirectUri,
      scopes: ['openid', 'profile'],
    },
    requiredUserScopes: ['openid'],
  };
}

/**
 * Creates a TokenManagerConfig from the server configuration.
 */
export function toTokenManagerConfig(config: McpServerConfig): TokenManagerConfig {
  return {
    amUrl: config.amUrl,
    realmPath: config.realmPath,
    client: config.client,
  };
}
