/**
 * MCP Agent Delegation Server Configuration
 *
 * Configuration can be provided via:
 * 1. Environment variables (for local development)
 * 2. MCP server initialization (when hosted by an MCP client)
 * 3. Programmatic configuration (when used as a library)
 *
 * @packageDocumentation
 */

import type { ConfidentialClientConfig, TokenManagerConfig } from '@pingidentity/aic-mcp-sdk';

/**
 * Configuration for the agent delegation server.
 */
export interface DelegationServerConfig {
  /** PingOne Advanced Identity Cloud URL */
  readonly amUrl: string;
  /** OAuth realm path */
  readonly realmPath: string;
  /** Confidential client configuration for this MCP server */
  readonly client: ConfidentialClientConfig;
  /** Downstream API audience for token exchange */
  readonly downstreamAudience: string;
  /** Scopes to request when exchanging tokens for downstream API */
  readonly downstreamScopes: readonly string[];
  /**
   * Accepted token audiences for incoming requests.
   * This allows the server to accept tokens issued for different clients
   * (e.g., public clients used by MCP Inspector) while using its own
   * confidential client for outbound operations like token exchange.
   */
  readonly acceptedAudiences?: readonly string[];
}

/**
 * Options for creating server configuration.
 * All fields are optional - defaults come from environment or sensible defaults.
 */
export interface DelegationServerConfigOptions {
  /** Override AM URL (default: AM_URL env var) */
  readonly amUrl?: string;
  /** Override realm path (default: AM_REALM_PATH env var or /am/oauth2/realms/root/realms/alpha) */
  readonly realmPath?: string;
  /** Override client ID (default: AM_CLIENT_ID env var) */
  readonly clientId?: string;
  /** Override client secret (default: AM_CLIENT_SECRET env var) */
  readonly clientSecret?: string;
  /** Override redirect URI (default: http://localhost:3000/callback) */
  readonly redirectUri?: string;
  /** Override client scopes (default: ['openid']) */
  readonly clientScopes?: readonly string[];
  /** Override downstream API audience (default: DOWNSTREAM_API_AUDIENCE env var) */
  readonly downstreamAudience?: string;
  /** Override downstream API scopes (default: DOWNSTREAM_API_SCOPES env var or ['read']) */
  readonly downstreamScopes?: readonly string[];
  /**
   * Accepted token audiences (default: ACCEPTED_AUDIENCES env var, space-separated).
   * If not specified, defaults to accepting the server's own client ID.
   */
  readonly acceptedAudiences?: readonly string[];
}

/**
 * Creates the delegation server configuration.
 *
 * @param options - Optional overrides for configuration values
 * @returns Complete server configuration
 * @throws Error if required values are missing
 *
 * @example
 * ```typescript
 * // Use environment variables
 * const config = createDelegationServerConfig();
 *
 * // Override specific values
 * const config = createDelegationServerConfig({
 *   amUrl: 'https://my-tenant.forgeblocks.com',
 *   downstreamAudience: 'https://api.internal.com',
 * });
 *
 * // Fully programmatic (no env vars needed)
 * const config = createDelegationServerConfig({
 *   amUrl: 'https://my-tenant.forgeblocks.com',
 *   clientId: 'my-mcp-server',
 *   clientSecret: 'secret',
 *   downstreamAudience: 'https://api.example.com',
 * });
 * ```
 */
export function createDelegationServerConfig(
  options: DelegationServerConfigOptions = {}
): DelegationServerConfig {
  // Resolve values with priority: options > env > defaults
  const amUrl = options.amUrl ?? process.env['AM_URL'];
  const clientId = options.clientId ?? process.env['AM_CLIENT_ID'];
  const clientSecret = options.clientSecret ?? process.env['AM_CLIENT_SECRET'];
  const realmPath =
    options.realmPath ?? process.env['AM_REALM_PATH'] ?? '/am/oauth2/realms/root/realms/alpha';
  const redirectUri = options.redirectUri ?? 'http://localhost:3000/callback';
  const clientScopes = options.clientScopes ?? ['openid'];
  const downstreamAudience =
    options.downstreamAudience ??
    process.env['DOWNSTREAM_API_AUDIENCE'] ??
    'https://api.example.com';
  const downstreamScopes = options.downstreamScopes ??
    parseScopes(process.env['DOWNSTREAM_API_SCOPES']) ?? ['read'];
  const acceptedAudiences =
    options.acceptedAudiences ?? parseScopes(process.env['ACCEPTED_AUDIENCES']);

  // Validate required fields
  if (!amUrl) {
    throw new Error(
      'AM_URL is required. Provide via options.amUrl or AM_URL environment variable.'
    );
  }

  if (!clientId) {
    throw new Error(
      'Client ID is required. Provide via options.clientId or AM_CLIENT_ID environment variable.'
    );
  }

  if (!clientSecret) {
    throw new Error(
      'Client secret is required. Provide via options.clientSecret or AM_CLIENT_SECRET environment variable.'
    );
  }

  const result: DelegationServerConfig = {
    amUrl,
    realmPath,
    client: {
      clientType: 'confidential',
      clientId,
      clientSecret,
      redirectUri,
      scopes: [...clientScopes],
    },
    downstreamAudience,
    downstreamScopes,
  };

  if (acceptedAudiences !== undefined) {
    return { ...result, acceptedAudiences };
  }

  return result;
}

/**
 * Creates a TokenManagerConfig from the server configuration.
 */
export function toTokenManagerConfig(config: DelegationServerConfig): TokenManagerConfig {
  return {
    amUrl: config.amUrl,
    realmPath: config.realmPath,
    client: config.client,
  };
}

/**
 * Parses a space-separated scope string into an array.
 */
function parseScopes(scopes: string | undefined): readonly string[] | undefined {
  if (!scopes) return undefined;
  return scopes.split(' ').filter((s) => s.length > 0);
}
