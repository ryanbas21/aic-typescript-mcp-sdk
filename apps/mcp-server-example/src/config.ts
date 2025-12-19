/**
 * MCP Server Configuration Module
 *
 * @packageDocumentation
 */

import type { ConfidentialClientConfig, TokenManagerConfig } from '@pingidentity/aic-mcp-sdk';

/**
 * MCP Server OAuth Configuration.
 */
export interface McpServerConfig {
  /** PingOne Advanced Identity Cloud URL */
  readonly amUrl: string;
  /** OAuth realm path */
  readonly realmPath: string;
  /** Confidential client configuration */
  readonly client: ConfidentialClientConfig;
  /** Scopes required from users to access protected tools */
  readonly requiredUserScopes: readonly string[];
}

/**
 * Creates the MCP server configuration from environment variables.
 */
export function createServerConfig(): McpServerConfig {
  const amUrl = process.env['AM_URL'];
  const clientId = process.env['AM_CLIENT_ID'];
  const clientSecret = process.env['AM_CLIENT_SECRET'];
  const realmPath = process.env['AM_REALM_PATH'] ?? '/am/oauth2/realms/root/realms/alpha';
  const serverUrl = process.env['MCP_SERVER_URL'] ?? 'http://127.0.0.1:3000';
  const redirectUri = process.env['OAUTH_REDIRECT_URI'] ?? `${serverUrl}/oauth/callback`;

  if (amUrl === undefined || amUrl.length === 0) {
    throw new Error('AM_URL is required');
  }

  if (clientId === undefined || clientId.length === 0) {
    throw new Error('AM_CLIENT_ID is required');
  }

  if (clientSecret === undefined || clientSecret.length === 0) {
    throw new Error('AM_CLIENT_SECRET is required');
  }

  return {
    amUrl,
    realmPath,
    client: {
      clientType: 'confidential',
      clientId,
      clientSecret,
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
