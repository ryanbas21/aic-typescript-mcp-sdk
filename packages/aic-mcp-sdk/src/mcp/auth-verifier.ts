import type { TokenValidator } from '../validation/types.js';
import type {
  AmVerifierConfig,
  AmVerifierConfigWithSecret,
  McpAuthInfo,
  OAuthTokenVerifier,
} from './types.js';
import { AuthenticationError } from './types.js';
import { createTokenValidator } from '../validation/token-validator.js';

/**
 * Creates an OAuthTokenVerifier that validates tokens against AM.
 *
 * This adapter bridges our TokenValidator to the MCP SDK's OAuthTokenVerifier interface,
 * allowing integration with MCP's built-in auth middleware.
 *
 * @param config - AM configuration
 * @returns An OAuthTokenVerifier instance
 *
 * @example
 * ```typescript
 * import { createAmVerifier } from '@anthropic/aic-mcp-sdk';
 * import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth';
 *
 * const verifier = createAmVerifier({
 *   amUrl: 'https://auth.example.com',
 *   clientId: 'my-client',
 *   clientSecret: 'my-secret',
 * });
 *
 * // Use with MCP's bearer auth middleware (HTTP transport)
 * app.use(requireBearerAuth({ verifier }));
 * ```
 */
export const createAmVerifier = (
  config: AmVerifierConfig | AmVerifierConfigWithSecret
): OAuthTokenVerifier => {
  const validator = createTokenValidator(config);
  return createAmVerifierFromValidator(validator);
};

/**
 * Creates an OAuthTokenVerifier from an existing TokenValidator.
 *
 * Use this when you need more control over the validator configuration
 * or want to share a validator instance.
 *
 * @param validator - An existing TokenValidator instance
 * @returns An OAuthTokenVerifier instance
 *
 * @example
 * ```typescript
 * import { createTokenValidator, createAmVerifierFromValidator } from '@anthropic/aic-mcp-sdk';
 *
 * const validator = createTokenValidator({
 *   amUrl: 'https://auth.example.com',
 *   clientId: 'my-client',
 *   clientSecret: 'my-secret',
 * });
 *
 * const verifier = createAmVerifierFromValidator(validator);
 * ```
 */
export const createAmVerifierFromValidator = (validator: TokenValidator): OAuthTokenVerifier => {
  const verifyAccessToken = async (token: string): Promise<McpAuthInfo> => {
    const result = await validator.validate(token);

    if (!result.valid) {
      throw new AuthenticationError(result);
    }

    const scopes = result.claims.scope?.split(' ').filter((s) => s.length > 0) ?? [];

    return {
      token,
      clientId: result.claims.client_id ?? '',
      scopes,
      expiresAt: result.claims.exp,
      extra: {
        sub: result.claims.sub,
        iss: result.claims.iss,
        aud: result.claims.aud,
      },
    };
  };

  return { verifyAccessToken };
};
