import type { TokenValidator } from '../validation/types.js';
import type { McpAuthInfo, WithAuthOptions, TokenExtractorConfig } from './types.js';
import { AuthenticationError, AuthorizationError } from './types.js';
import { getMissingScopes, parseScopes } from '../validation/scopes.js';

/** Default environment variable for access token */
const DEFAULT_ENV_VAR = 'AM_ACCESS_TOKEN';

/** Default meta field for per-request token */
const DEFAULT_META_FIELD = 'accessToken';

/**
 * Request metadata that may contain an access token.
 */
type RequestMeta = Readonly<Record<string, unknown>>;

/**
 * The extra context passed to MCP tool handlers.
 * We define a minimal interface to avoid tight coupling with MCP SDK.
 */
interface ToolHandlerExtra {
  readonly authInfo?: McpAuthInfo;
  readonly _meta?: RequestMeta;
  readonly [key: string]: unknown;
}

/**
 * Generic tool callback type compatible with MCP SDK.
 */
type ToolCallback<TArgs, TResult> = (
  args: TArgs,
  extra: ToolHandlerExtra
) => TResult | Promise<TResult>;

/**
 * Extracts a token from environment variable.
 */
const extractTokenFromEnv = (envVar: string): string | undefined => {
  return process.env[envVar];
};

/**
 * Extracts a token from request _meta.
 */
const extractTokenFromMeta = (
  meta: RequestMeta | undefined,
  metaField: string
): string | undefined => {
  if (meta === undefined) {
    return undefined;
  }
  const token = meta[metaField];
  return typeof token === 'string' ? token : undefined;
};

/**
 * Creates a token extractor function based on configuration.
 */
const createTokenExtractor = (
  config: TokenExtractorConfig
): ((extra: ToolHandlerExtra) => string | undefined) => {
  const envVar = config.envVar ?? DEFAULT_ENV_VAR;
  const metaField = config.metaField ?? DEFAULT_META_FIELD;
  const source = config.stdioTokenSource ?? 'both';

  // Custom function source
  if (typeof source === 'function') {
    return source;
  }

  return (extra: ToolHandlerExtra): string | undefined => {
    switch (source) {
      case 'env':
        return extractTokenFromEnv(envVar);
      case 'meta':
        return extractTokenFromMeta(extra._meta, metaField);
      case 'both':
      default:
        // Try meta first, fall back to env
        return extractTokenFromMeta(extra._meta, metaField) ?? extractTokenFromEnv(envVar);
    }
  };
};

/**
 * Validates that all required scopes are present.
 * Throws AuthorizationError if any scopes are missing.
 */
const checkRequiredScopes = (
  requiredScopes: readonly string[],
  presentScopes: readonly string[]
): void => {
  const missing = getMissingScopes(requiredScopes, presentScopes);
  if (missing.length > 0) {
    throw new AuthorizationError(requiredScopes, presentScopes);
  }
};

/**
 * Configuration for creating an auth wrapper.
 */
export interface CreateWithAuthConfig {
  /** The token validator instance */
  readonly validator: TokenValidator;
  /** Token extraction configuration */
  readonly tokenExtractor?: TokenExtractorConfig;
  /**
   * Accepted token audiences.
   * If specified, tokens must have an audience matching one of these values.
   * This allows accepting tokens from multiple clients (e.g., public clients
   * used by MCP Inspector) while using a different confidential client for
   * outbound operations.
   */
  readonly acceptedAudiences?: readonly string[];
}

/**
 * Creates a withAuth wrapper function bound to a specific validator.
 *
 * This is the recommended approach for protecting multiple tools with
 * the same validator configuration.
 *
 * @param config - Validator and token extraction configuration
 * @returns A withAuth function for wrapping tool handlers
 *
 * @example
 * ```typescript
 * import { createTokenValidator, createWithAuth } from '@anthropic/aic-mcp-sdk';
 *
 * const validator = createTokenValidator({
 *   amUrl: 'https://auth.example.com',
 *   clientId: 'my-client',
 *   clientSecret: 'my-secret',
 * });
 *
 * const withAuth = createWithAuth({ validator });
 *
 * server.registerTool('my_tool', { ... },
 *   withAuth({ requiredScopes: ['read'] }, async (args, extra) => {
 *     // extra.authInfo is guaranteed to exist
 *     console.log('User:', extra.authInfo.extra?.sub);
 *     return { content: [{ type: 'text', text: 'Success' }] };
 *   })
 * );
 * ```
 */
export const createWithAuth = (config: CreateWithAuthConfig): WithAuthFn => {
  const { validator, tokenExtractor: extractorConfig = {}, acceptedAudiences } = config;
  const extractToken = createTokenExtractor(extractorConfig);

  /**
   * Wraps a tool handler with authentication and optional scope validation.
   *
   * @param options - Auth options (required scopes, etc.)
   * @param handler - The tool handler to wrap
   * @returns A wrapped handler that validates auth before execution
   */
  const withAuth = <TArgs, TResult>(
    options: WithAuthOptions,
    handler: ToolCallback<TArgs, TResult>
  ): ToolCallback<TArgs, TResult> => {
    return async (args: TArgs, extra: ToolHandlerExtra): Promise<TResult> => {
      // If authInfo already exists (e.g., from HTTP middleware), use it
      let authInfo = extra.authInfo;

      if (authInfo === undefined) {
        // Extract and validate token (stdio path)
        const token = extractToken(extra);

        if (token === undefined) {
          const authenticationInfo = await validator.getAuthenticationInfo();
          const failure =
            authenticationInfo !== undefined
              ? {
                  valid: false as const,
                  error: 'MISSING_TOKEN' as const,
                  message: 'No access token provided',
                  authenticationInfo,
                }
              : {
                  valid: false as const,
                  error: 'MISSING_TOKEN' as const,
                  message: 'No access token provided',
                };
          throw new AuthenticationError(failure);
        }

        const validationOptions: {
          requiredScopes?: string[];
          audience?: readonly string[];
        } = {};

        if (options.requiredScopes !== undefined && options.requiredScopes.length > 0) {
          validationOptions.requiredScopes = [...options.requiredScopes];
        }

        if (acceptedAudiences !== undefined && acceptedAudiences.length > 0) {
          validationOptions.audience = acceptedAudiences;
        }

        const result = await validator.validate(token, validationOptions);

        if (!result.valid) {
          throw new AuthenticationError(result);
        }

        // Build authInfo from validation result
        const scopes = parseScopes(result.claims.scope);

        // Include all claims in extra for delegation chain inspection
        const extraClaims: Record<string, unknown> = {
          sub: result.claims.sub,
          iss: result.claims.iss,
          aud: result.claims.aud,
          exp: result.claims.exp,
          iat: result.claims.iat,
        };

        // Include act claim if present (for delegation chain)
        const actClaim = result.claims.act;
        if (actClaim !== undefined) {
          extraClaims['act'] = actClaim;
        }

        authInfo = {
          token,
          clientId: result.claims.client_id ?? '',
          scopes,
          expiresAt: result.claims.exp,
          extra: extraClaims,
        };
      } else if (options.requiredScopes !== undefined && options.requiredScopes.length > 0) {
        // authInfo exists but we need to validate scopes
        checkRequiredScopes(options.requiredScopes, authInfo.scopes);
      }

      // Call the handler with authInfo guaranteed
      const extraWithAuth: ToolHandlerExtra = {
        ...extra,
        authInfo,
      };

      return handler(args, extraWithAuth);
    };
  };

  return withAuth;
};

/**
 * Type for the withAuth function returned by createWithAuth.
 */
export type WithAuthFn = <TArgs, TResult>(
  options: WithAuthOptions,
  handler: ToolCallback<TArgs, TResult>
) => ToolCallback<TArgs, TResult>;
