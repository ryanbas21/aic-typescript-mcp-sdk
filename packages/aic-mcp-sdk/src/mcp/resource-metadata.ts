/**
 * OAuth 2.0 Protected Resource Metadata per RFC 9728.
 * Used for MCP /.well-known/oauth-protected-resource endpoint.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9728
 * @see https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization
 */

/**
 * OAuth 2.0 Protected Resource Metadata per RFC 9728.
 * This is the response format for the /.well-known/oauth-protected-resource endpoint.
 */
export interface ProtectedResourceMetadata {
  /**
   * The protected resource's identifier URL.
   * MUST be identical to the resource URL the client used.
   * @required
   */
  readonly resource: string;

  /**
   * Array of authorization server issuer URLs.
   * Required by MCP spec, clients use this to discover where to authenticate.
   * @required
   */
  readonly authorization_servers: readonly string[];

  /**
   * OAuth 2.0 scope values supported by this resource.
   * Helps clients know what scopes to request.
   */
  readonly scopes_supported?: readonly string[];

  /**
   * Methods supported for delivering the access token.
   * MCP servers typically only support "header" (Authorization header).
   */
  readonly bearer_methods_supported?: readonly ('header' | 'body' | 'query')[];

  /**
   * URL of the resource's JWK Set for signature verification.
   */
  readonly jwks_uri?: string;

  /**
   * URL of developer documentation for this resource.
   */
  readonly resource_documentation?: string;

  /**
   * DPoP signing algorithms supported by this resource.
   */
  readonly dpop_signing_alg_values_supported?: readonly string[];

  /**
   * Whether DPoP-bound access tokens are required.
   */
  readonly dpop_bound_access_tokens_required?: boolean;

  /**
   * Human-readable name for this resource.
   */
  readonly resource_name?: string;

  /**
   * URL of the resource's privacy policy.
   */
  readonly resource_policy_uri?: string;

  /**
   * URL of the resource's terms of service.
   */
  readonly resource_tos_uri?: string;
}

/**
 * Configuration for creating protected resource metadata.
 */
export interface ProtectedResourceMetadataConfig {
  /**
   * The protected resource's identifier URL (your MCP server URL).
   * @required
   */
  readonly resourceUrl: string;

  /**
   * Authorization server issuer URL(s).
   * Can be a single issuer or array of issuers.
   * @required
   */
  readonly authorizationServers: string | readonly string[];

  /**
   * OAuth 2.0 scopes supported by this resource.
   */
  readonly scopesSupported?: readonly string[];

  /**
   * URL of developer documentation.
   */
  readonly documentationUrl?: string;

  /**
   * Human-readable name for this resource.
   */
  readonly resourceName?: string;
}

/**
 * Creates a protected resource metadata object per RFC 9728.
 * This should be returned from your /.well-known/oauth-protected-resource endpoint.
 *
 * @param config - Configuration for the protected resource
 * @returns RFC 9728 compliant metadata object
 *
 * @example
 * ```typescript
 * const metadata = createProtectedResourceMetadata({
 *   resourceUrl: 'https://mcp.example.com',
 *   authorizationServers: 'https://auth.example.com/oauth2/alpha',
 *   scopesSupported: ['openid', 'mcp:tools'],
 *   resourceName: 'My MCP Server',
 * });
 *
 * // In your HTTP handler:
 * app.get('/.well-known/oauth-protected-resource', (req, res) => {
 *   res.json(metadata);
 * });
 * ```
 */
export const createProtectedResourceMetadata = (
  config: ProtectedResourceMetadataConfig
): ProtectedResourceMetadata => {
  const authServers = Array.isArray(config.authorizationServers)
    ? config.authorizationServers
    : [config.authorizationServers];

  const metadata: ProtectedResourceMetadata = {
    resource: config.resourceUrl,
    authorization_servers: authServers,
    bearer_methods_supported: ['header'],
  };

  // Add optional fields only if provided
  if (config.scopesSupported !== undefined && config.scopesSupported.length > 0) {
    return {
      ...metadata,
      scopes_supported: config.scopesSupported,
      ...(config.documentationUrl !== undefined
        ? { resource_documentation: config.documentationUrl }
        : {}),
      ...(config.resourceName !== undefined ? { resource_name: config.resourceName } : {}),
    };
  }

  if (config.documentationUrl !== undefined) {
    return {
      ...metadata,
      resource_documentation: config.documentationUrl,
      ...(config.resourceName !== undefined ? { resource_name: config.resourceName } : {}),
    };
  }

  if (config.resourceName !== undefined) {
    return {
      ...metadata,
      resource_name: config.resourceName,
    };
  }

  return metadata;
};

/**
 * WWW-Authenticate challenge parameters for 401 responses.
 */
export interface WwwAuthenticateChallenge {
  /**
   * Authentication scheme. Use "Bearer" for standard OAuth 2.0.
   * @default "Bearer"
   */
  readonly scheme?: 'Bearer' | 'DPoP';

  /**
   * URL to the protected resource metadata endpoint.
   * This is typically: https://your-server.com/.well-known/oauth-protected-resource
   * @required
   */
  readonly resourceMetadataUrl: string;

  /**
   * Optional realm parameter for the authentication challenge.
   */
  readonly realm?: string;

  /**
   * Optional scope parameter indicating required scopes.
   */
  readonly scope?: string;

  /**
   * Optional error code (e.g., "invalid_token", "insufficient_scope").
   */
  readonly error?: 'invalid_token' | 'insufficient_scope' | 'invalid_request';

  /**
   * Optional human-readable error description.
   */
  readonly errorDescription?: string;
}

/**
 * Formats a WWW-Authenticate header value per RFC 6750 and RFC 9728.
 * This header tells clients where to find authentication information.
 *
 * @param challenge - Challenge parameters
 * @returns Formatted WWW-Authenticate header value
 *
 * @example
 * ```typescript
 * const header = formatWwwAuthenticateHeader({
 *   resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
 *   realm: 'mcp',
 * });
 * // Returns: 'Bearer realm="mcp", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
 *
 * // In your HTTP handler:
 * res.status(401)
 *   .header('WWW-Authenticate', header)
 *   .json({ error: 'unauthorized' });
 * ```
 */
export const formatWwwAuthenticateHeader = (challenge: WwwAuthenticateChallenge): string => {
  const scheme = challenge.scheme ?? 'Bearer';
  const params: string[] = [];

  if (challenge.realm !== undefined) {
    params.push(`realm="${challenge.realm}"`);
  }

  // resource_metadata is the RFC 9728 parameter
  params.push(`resource_metadata="${challenge.resourceMetadataUrl}"`);

  if (challenge.scope !== undefined) {
    params.push(`scope="${challenge.scope}"`);
  }

  if (challenge.error !== undefined) {
    params.push(`error="${challenge.error}"`);
  }

  if (challenge.errorDescription !== undefined) {
    params.push(`error_description="${challenge.errorDescription}"`);
  }

  return params.length > 0 ? `${scheme} ${params.join(', ')}` : scheme;
};

/**
 * Parses a WWW-Authenticate header value into its components.
 * Useful for clients processing 401 responses.
 *
 * @param header - The WWW-Authenticate header value
 * @returns Parsed challenge parameters, or undefined if parsing fails
 *
 * @example
 * ```typescript
 * const challenge = parseWwwAuthenticateHeader(
 *   'Bearer realm="mcp", resource_metadata="https://example.com/.well-known/oauth-protected-resource"'
 * );
 * // Returns: { scheme: 'Bearer', realm: 'mcp', resourceMetadataUrl: 'https://...' }
 * ```
 */
export const parseWwwAuthenticateHeader = (
  header: string
): (WwwAuthenticateChallenge & { readonly scheme: 'Bearer' | 'DPoP' }) | undefined => {
  const schemeMatch = /^(Bearer|DPoP)\s*/i.exec(header);
  if (schemeMatch === null) {
    return undefined;
  }

  const scheme = schemeMatch[1] as 'Bearer' | 'DPoP';
  const paramsString = header.slice(schemeMatch[0].length);

  // Parse key="value" pairs
  const paramRegex = /(\w+)="([^"]*)"/g;
  const params: Record<string, string> = {};
  let match: RegExpExecArray | null;

  while ((match = paramRegex.exec(paramsString)) !== null) {
    const key = match[1];
    const value = match[2];
    if (key !== undefined && value !== undefined) {
      params[key] = value;
    }
  }

  const resourceMetadataUrl = params['resource_metadata'];
  if (resourceMetadataUrl === undefined) {
    return undefined;
  }

  return {
    scheme,
    resourceMetadataUrl,
    ...(params['realm'] !== undefined ? { realm: params['realm'] } : {}),
    ...(params['scope'] !== undefined ? { scope: params['scope'] } : {}),
    ...(params['error'] !== undefined
      ? { error: params['error'] as 'invalid_token' | 'insufficient_scope' | 'invalid_request' }
      : {}),
    ...(params['error_description'] !== undefined
      ? { errorDescription: params['error_description'] }
      : {}),
  };
};
