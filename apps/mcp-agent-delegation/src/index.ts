#!/usr/bin/env node

/**
 * MCP Server: Agent-to-Agent Delegation Demo
 *
 * This example demonstrates the complete agent-to-agent delegation flow:
 *
 * 1. User authenticates with the MCP client (e.g., Claude Desktop)
 * 2. MCP client passes user's token to this MCP server
 * 3. MCP server validates the incoming token
 * 4. MCP server exchanges the user token for a delegated token (RFC 8693)
 * 5. MCP server calls downstream API with the delegated token
 * 6. Delegation chain is preserved: User → MCP Client → MCP Server → Downstream API
 *
 * The delegation chain allows downstream services to:
 * - Know the original user (subject)
 * - Know which agents acted on behalf of the user (actor chain)
 * - Apply appropriate authorization policies
 *
 * @packageDocumentation
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  createTokenValidator,
  createTokenManager,
  createMemoryStorage,
  createWithAuth,
  AuthenticationError,
  AuthorizationError,
  getDelegationContext,
  isDelegatedToken,
  validateDelegationChain,
  type TokenValidator,
  type TokenManager,
  type TokenSet,
  type DelegationContext,
  type TokenClaims,
} from '@pingidentity/aic-mcp-sdk';
import {
  createDelegationServerConfig,
  toTokenManagerConfig,
  type DelegationServerConfig,
  type DelegationServerConfigOptions,
} from './config.js';

// Re-export config types for programmatic usage
export type { DelegationServerConfig, DelegationServerConfigOptions };
export { createDelegationServerConfig };

// ============================================================================
// Types
// ============================================================================

interface McpErrorResponse {
  [x: string]: unknown;
  content: [{ type: 'text'; text: string }];
  isError: true;
}

// ============================================================================
// Delegation Manager
// ============================================================================

interface DelegationManager {
  readonly validator: TokenValidator;
  readonly exchangeToken: (
    userToken: string,
    audience: string,
    scopes?: readonly string[]
  ) => Promise<{ success: true; tokens: TokenSet } | { success: false; error: string }>;
  readonly getDelegationInfo: (claims: Record<string, unknown>) => DelegationContext | undefined;
  readonly buildTokenClaims: (claims: Record<string, unknown>) => TokenClaims | undefined;
}

function createDelegationManager(config: DelegationServerConfig): DelegationManager {
  const storage = createMemoryStorage();

  const tokenManager: TokenManager = createTokenManager(toTokenManagerConfig(config), storage);

  const validator: TokenValidator = createTokenValidator({
    amUrl: config.amUrl,
    clientId: config.client.clientId,
    clientSecret: config.client.clientSecret,
    realmPath: config.realmPath,
  });

  const exchangeToken: DelegationManager['exchangeToken'] = async (userToken, audience, scopes) => {
    const request: {
      subjectToken: string;
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token';
      audience: string;
      scope?: string;
    } = {
      subjectToken: userToken,
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      audience,
    };

    if (scopes !== undefined && scopes.length > 0) {
      (request as { scope: string }).scope = scopes.join(' ');
    }

    const result = await tokenManager.exchangeToken(request);

    if (result.success) {
      return { success: true, tokens: result.tokens };
    }

    return { success: false, error: result.error.message };
  };

  const buildTokenClaims: DelegationManager['buildTokenClaims'] = (claims) => {
    const sub = claims['sub'];
    const iss = claims['iss'];
    const aud = claims['aud'];
    const exp = claims['exp'];
    const iat = claims['iat'];
    const act = claims['act'];

    if (
      typeof sub !== 'string' ||
      typeof iss !== 'string' ||
      typeof exp !== 'number' ||
      typeof iat !== 'number'
    ) {
      return undefined;
    }

    const tokenClaims: TokenClaims = {
      sub,
      iss,
      aud: aud as string | readonly string[],
      exp,
      iat,
    };

    if (act !== undefined && typeof act === 'object' && act !== null && 'sub' in act) {
      return {
        ...tokenClaims,
        act: act as TokenClaims['act'],
      };
    }

    return tokenClaims;
  };

  const getDelegationInfo: DelegationManager['getDelegationInfo'] = (claims) => {
    const tokenClaims = buildTokenClaims(claims);
    if (!tokenClaims) return undefined;
    return getDelegationContext(tokenClaims);
  };

  return {
    validator,
    exchangeToken,
    getDelegationInfo,
    buildTokenClaims,
  };
}

// ============================================================================
// Error Handling
// ============================================================================

function formatError(error: AuthenticationError | AuthorizationError): McpErrorResponse {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            error: error instanceof AuthorizationError ? 'insufficient_scope' : error.code,
            message: error.message,
          },
          null,
          2
        ),
      },
    ],
    isError: true,
  };
}

function createErrorHandler<TArgs, TExtra, TResult>(
  handler: (args: TArgs, extra: TExtra) => TResult | Promise<TResult>
): (args: TArgs, extra: TExtra) => Promise<TResult | McpErrorResponse> {
  return async (args: TArgs, extra: TExtra) => {
    try {
      return await handler(args, extra);
    } catch (error) {
      if (error instanceof AuthenticationError || error instanceof AuthorizationError) {
        return formatError(error);
      }
      throw error;
    }
  };
}

// ============================================================================
// Server Creation
// ============================================================================

/**
 * Creates the MCP server with delegation tools.
 *
 * @param config - Server configuration
 * @returns Configured McpServer instance
 *
 * @example
 * ```typescript
 * import { createServer, createDelegationServerConfig } from '@pingidentity/mcp-agent-delegation';
 *
 * const config = createDelegationServerConfig({
 *   amUrl: 'https://my-tenant.forgeblocks.com',
 *   clientId: 'my-mcp-server',
 *   clientSecret: 'secret',
 *   downstreamAudience: 'https://api.example.com',
 * });
 *
 * const server = createServer(config);
 * ```
 */
export function createServer(config: DelegationServerConfig): McpServer {
  const delegation = createDelegationManager(config);
  const withAuth = createWithAuth({ validator: delegation.validator });

  const server = new McpServer({
    name: 'agent-delegation-server',
    version: '0.0.1',
  });

  // -------------------------------------------------------------------------
  // Tool: Inspect incoming token's delegation chain
  // -------------------------------------------------------------------------

  server.registerTool(
    'inspect_delegation',
    {
      description:
        'Inspect the delegation chain of your current token. Shows who the original user is and which agents have acted on their behalf.',
      inputSchema: {},
    },
    createErrorHandler(
      withAuth({ requiredScopes: ['openid'] }, (_args, extra) => {
        const claims = extra.authInfo?.extra as Record<string, unknown> | undefined;

        if (!claims) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({ error: 'No token claims available' }, null, 2),
              },
            ],
            isError: true,
          };
        }

        const delegationInfo = delegation.getDelegationInfo(claims);

        if (!delegationInfo) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({ error: 'Could not parse delegation info' }, null, 2),
              },
            ],
            isError: true,
          };
        }

        const response = {
          message: delegationInfo.isDelegated
            ? 'This is a delegated token with an actor chain'
            : 'This is a direct user token (no delegation)',
          delegation: {
            originalUser: delegationInfo.subject,
            isDelegated: delegationInfo.isDelegated,
            delegationDepth: delegationInfo.depth,
            immediateActor: delegationInfo.immediateActor ?? null,
            fullActorChain: delegationInfo.chain,
          },
          explanation: delegationInfo.isDelegated
            ? `The token was issued for user "${delegationInfo.subject}" but is being used by agent "${delegationInfo.immediateActor?.sub ?? 'unknown'}". The full chain shows all intermediaries.`
            : `The token belongs directly to user "${delegationInfo.subject}" with no intermediary agents.`,
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(response, null, 2),
            },
          ],
        };
      })
    )
  );

  // -------------------------------------------------------------------------
  // Tool: Exchange token for downstream API access
  // -------------------------------------------------------------------------

  server.registerTool(
    'exchange_for_downstream',
    {
      description: `Exchange your token to call a downstream API (${config.downstreamAudience}). This adds this MCP server to the delegation chain.`,
      inputSchema: {
        customAudience: z
          .string()
          .optional()
          .describe('Optional: Override the default downstream API audience'),
        customScopes: z
          .array(z.string())
          .optional()
          .describe('Optional: Request specific scopes for the downstream API'),
      },
    },
    createErrorHandler(
      withAuth({ requiredScopes: ['openid'] }, async ({ customAudience, customScopes }, extra) => {
        const userToken = extra.authInfo?.token;

        if (!userToken) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({ error: 'No token available for exchange' }, null, 2),
              },
            ],
            isError: true,
          };
        }

        const audience = customAudience ?? config.downstreamAudience;
        const scopes = customScopes ?? config.downstreamScopes;

        console.error(`[exchange] Exchanging token for audience: ${audience}`);

        const result = await delegation.exchangeToken(userToken, audience, scopes);

        if (!result.success) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(
                  {
                    error: 'Token exchange failed',
                    details: result.error,
                    hint: 'Ensure the authorization server supports RFC 8693 token exchange and the audience is configured.',
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }

        // Analyze the original token - authInfo is guaranteed by withAuth
        const claims = extra.authInfo.extra as Record<string, unknown> | undefined;
        const originalDelegation =
          claims !== undefined ? delegation.getDelegationInfo(claims) : undefined;

        const response = {
          message: 'Token exchanged successfully',
          exchangedToken: {
            audience,
            scopes: result.tokens.scopes,
            expiresAt: new Date(result.tokens.expiresAt).toISOString(),
          },
          delegationChain: {
            before: {
              subject: originalDelegation?.subject ?? 'unknown',
              depth: originalDelegation?.depth ?? 0,
              actors: originalDelegation?.chain.map((a) => a.sub) ?? [],
            },
            after: {
              note: 'The exchanged token now includes this MCP server in the actor chain',
              expectedDepth: (originalDelegation?.depth ?? 0) + 1,
              newActor: config.client.clientId,
            },
          },
          usage: {
            description: `Use this token to call ${audience}`,
            tokenPreview: `${result.tokens.accessToken.substring(0, 20)}...`,
          },
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(response, null, 2),
            },
          ],
        };
      })
    )
  );

  // -------------------------------------------------------------------------
  // Tool: Validate a delegation chain
  // -------------------------------------------------------------------------

  server.registerTool(
    'validate_chain',
    {
      description:
        'Validate the delegation chain of your token against security policies (max depth, required/forbidden actors).',
      inputSchema: {
        maxDepth: z.number().optional().describe('Maximum allowed delegation depth'),
        requiredActors: z
          .array(z.string())
          .optional()
          .describe('List of actor subject identifiers that MUST be in the delegation chain'),
        forbiddenActors: z
          .array(z.string())
          .optional()
          .describe('List of actor subject identifiers that must NOT be in the delegation chain'),
      },
    },
    createErrorHandler(
      withAuth(
        { requiredScopes: ['openid'] },
        ({ maxDepth, requiredActors, forbiddenActors }, extra) => {
          const claims = extra.authInfo?.extra as Record<string, unknown> | undefined;

          if (!claims) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: JSON.stringify({ error: 'No token claims available' }, null, 2),
                },
              ],
              isError: true,
            };
          }

          const tokenClaims = delegation.buildTokenClaims(claims);

          if (!tokenClaims) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: JSON.stringify({ error: 'Invalid token claims' }, null, 2),
                },
              ],
              isError: true,
            };
          }

          // Build validation options - only include defined values
          const validationOptions: {
            maxDepth?: number;
            requiredActors?: readonly string[];
            forbiddenActors?: readonly string[];
          } = {};

          if (maxDepth !== undefined) {
            validationOptions.maxDepth = maxDepth;
          }

          if (requiredActors !== undefined) {
            validationOptions.requiredActors = requiredActors;
          }

          if (forbiddenActors !== undefined) {
            validationOptions.forbiddenActors = forbiddenActors;
          }

          const validationResult = validateDelegationChain(tokenClaims, validationOptions);
          const delegationInfo = delegation.getDelegationInfo(claims);

          const response = {
            valid: validationResult.valid,
            message: validationResult.valid
              ? 'Delegation chain passes all validation checks'
              : 'Delegation chain failed validation',
            errors: validationResult.errors,
            chainDetails: {
              subject: delegationInfo?.subject,
              depth: delegationInfo?.depth,
              actors: delegationInfo?.chain.map((a) => a.sub),
            },
            policiesApplied: {
              maxDepth: maxDepth ?? 'not enforced',
              requiredActors: requiredActors ?? 'not enforced',
              forbiddenActors: forbiddenActors ?? 'not enforced',
            },
          };

          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(response, null, 2),
              },
            ],
          };
        }
      )
    )
  );

  // -------------------------------------------------------------------------
  // Tool: Simulate downstream API call
  // -------------------------------------------------------------------------

  server.registerTool(
    'call_downstream_api',
    {
      description:
        'Simulate calling a downstream API with a delegated token. Shows how the delegation chain is preserved.',
      inputSchema: {
        endpoint: z.string().describe('The API endpoint to call (simulated)'),
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).optional().describe('HTTP method'),
      },
    },
    createErrorHandler(
      withAuth({ requiredScopes: ['openid'] }, async ({ endpoint, method }, extra) => {
        const userToken = extra.authInfo?.token;
        const claims = extra.authInfo?.extra as Record<string, unknown> | undefined;

        if (!userToken || !claims) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({ error: 'No token available' }, null, 2),
              },
            ],
            isError: true,
          };
        }

        // Exchange token for downstream API
        const exchangeResult = await delegation.exchangeToken(
          userToken,
          config.downstreamAudience,
          config.downstreamScopes
        );

        if (!exchangeResult.success) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(
                  {
                    error: 'Failed to obtain delegated token',
                    details: exchangeResult.error,
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }

        const originalDelegation = delegation.getDelegationInfo(claims);

        // Simulate the API call
        const simulatedResponse = {
          simulation: true,
          apiCall: {
            method: method ?? 'GET',
            url: `${config.downstreamAudience}${endpoint}`,
            headers: {
              Authorization: `Bearer ${exchangeResult.tokens.accessToken.substring(0, 15)}...`,
            },
          },
          delegationFlow: {
            step1: {
              description: 'User authenticates with MCP client',
              subject: originalDelegation?.subject ?? 'user',
            },
            step2: {
              description: 'MCP client passes token to this MCP server',
              token: 'User token (possibly already delegated)',
              depth: originalDelegation?.depth ?? 0,
            },
            step3: {
              description: 'MCP server exchanges token for downstream API',
              actor: config.client.clientId,
              audience: config.downstreamAudience,
              newDepth: (originalDelegation?.depth ?? 0) + 1,
            },
            step4: {
              description: 'Downstream API receives request with delegation chain',
              canIdentify: {
                originalUser: originalDelegation?.subject,
                actingOnBehalf: config.client.clientId,
                fullChain: [
                  ...(originalDelegation?.chain.map((a) => a.sub) ?? []),
                  config.client.clientId,
                ],
              },
            },
          },
          securityBenefits: [
            'Downstream API knows the original user identity',
            'Downstream API can see the full delegation chain',
            'Audit logs can trace actions back to the original user',
            'Fine-grained authorization based on actor chain is possible',
          ],
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(simulatedResponse, null, 2),
            },
          ],
        };
      })
    )
  );

  // -------------------------------------------------------------------------
  // Tool: Check if token is delegated
  // -------------------------------------------------------------------------

  server.registerTool(
    'is_delegated',
    {
      description: 'Quick check: Is the current token a delegated token?',
      inputSchema: {},
    },
    createErrorHandler(
      withAuth({ requiredScopes: ['openid'] }, (_args, extra) => {
        const claims = extra.authInfo?.extra as Record<string, unknown> | undefined;

        if (!claims) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({ error: 'No claims available' }, null, 2),
              },
            ],
            isError: true,
          };
        }

        const tokenClaims = delegation.buildTokenClaims(claims);

        if (!tokenClaims) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({ error: 'Invalid claims' }, null, 2),
              },
            ],
            isError: true,
          };
        }

        const delegated = isDelegatedToken(tokenClaims);

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  isDelegated: delegated,
                  explanation: delegated
                    ? 'This token has an "act" claim, indicating it was obtained through token exchange'
                    : 'This token has no "act" claim, indicating direct user authentication',
                },
                null,
                2
              ),
            },
          ],
        };
      })
    )
  );

  return server;
}

// ============================================================================
// Main Entry Point (for CLI usage)
// ============================================================================

async function main(): Promise<void> {
  console.error('[server] Starting Agent Delegation MCP Server');

  // Load config - will use env vars if available, or throw helpful errors
  const config = createDelegationServerConfig();
  console.error(`[server] AM URL: ${config.amUrl}`);
  console.error(`[server] Client ID: ${config.client.clientId}`);
  console.error(`[server] Downstream API: ${config.downstreamAudience}`);

  const server = createServer(config);
  const transport = new StdioServerTransport();

  await server.connect(transport);
  console.error('[server] Connected via stdio');

  process.on('SIGINT', () => {
    console.error('[server] Shutting down...');
    server.close().catch(console.error);
    process.exit(0);
  });
}

// Only run main if this is the entry point
const isMainModule =
  Boolean(process.argv[1]?.endsWith('index.js')) || Boolean(process.argv[1]?.endsWith('index.ts'));
if (isMainModule) {
  main().catch((error: unknown) => {
    console.error('[server] Fatal error:', error);
    process.exit(1);
  });
}
