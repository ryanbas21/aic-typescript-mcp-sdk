#!/usr/bin/env node

/**
 * MCP Server Example with Authentication
 *
 * Demonstrates:
 * 1. Token validation on tool calls
 * 2. 401 responses with authorization URL for unauthenticated users
 * 3. User authentication flow (authorization code + PKCE)
 *
 * @packageDocumentation
 */

import 'dotenv/config';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { createWithAuth, AuthenticationError, AuthorizationError } from '@pingidentity/aic-mcp-sdk';
import { createServerConfig, type McpServerConfig } from './config.js';
import { createAuthManager, isAuthorizationUrlResult, type AuthManager } from './auth.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Todo item from JSONPlaceholder API
 */
interface Todo {
  readonly userId: number;
  readonly id: number;
  readonly title: string;
  readonly completed: boolean;
}

// ============================================================================
// API Helpers
// ============================================================================

const TYPICODE_BASE_URL = 'https://jsonplaceholder.typicode.com';

/**
 * Fetches todos from JSONPlaceholder API
 */
async function fetchTodos(userId?: number): Promise<readonly Todo[]> {
  const url =
    userId !== undefined
      ? `${TYPICODE_BASE_URL}/todos?userId=${String(userId)}`
      : `${TYPICODE_BASE_URL}/todos`;

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch todos: ${String(response.status)} ${response.statusText}`);
  }

  return (await response.json()) as readonly Todo[];
}

/**
 * Fetches a single todo by ID
 */
async function fetchTodoById(id: number): Promise<Todo> {
  const response = await fetch(`${TYPICODE_BASE_URL}/todos/${String(id)}`);

  if (!response.ok) {
    throw new Error(
      `Failed to fetch todo ${String(id)}: ${String(response.status)} ${response.statusText}`
    );
  }

  return (await response.json()) as Todo;
}

// ============================================================================
// Error Handling
// ============================================================================

/**
 * MCP error response format.
 * Note: MCP SDK requires mutable arrays and index signature for compatibility.
 */
interface McpErrorResponse {
  [x: string]: unknown;
  content: [{ type: 'text'; text: string }];
  isError: true;
}

/**
 * Formats an authentication/authorization error for MCP response.
 */
function formatAuthError(
  error: AuthenticationError | AuthorizationError,
  authorizationUrl?: string
): McpErrorResponse {
  if (error instanceof AuthorizationError) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              error: 'insufficient_scope',
              message: error.message,
              requiredScopes: error.requiredScopes,
              missingScopes: error.missingScopes,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            error: error.code,
            message: error.message,
            authorizationUrl,
          },
          null,
          2
        ),
      },
    ],
    isError: true,
  };
}

/**
 * Creates a wrapper that catches auth errors and returns MCP error responses.
 */
function createErrorHandler(
  _config: McpServerConfig,
  authManager: AuthManager
): <TArgs, TExtra, TResult>(
  handler: (args: TArgs, extra: TExtra) => TResult | Promise<TResult>
) => (args: TArgs, extra: TExtra) => Promise<TResult | McpErrorResponse> {
  return <TArgs, TExtra, TResult>(
    handler: (args: TArgs, extra: TExtra) => TResult | Promise<TResult>
  ) => {
    return async (args: TArgs, extra: TExtra) => {
      try {
        return await handler(args, extra);
      } catch (error) {
        if (error instanceof AuthenticationError || error instanceof AuthorizationError) {
          let authorizationUrl: string | undefined;

          // Generate authorization URL for missing token errors
          if (error instanceof AuthenticationError && error.code === 'MISSING_TOKEN') {
            try {
              const authResult = await authManager.startUserAuth();
              if (isAuthorizationUrlResult(authResult)) {
                authorizationUrl = authResult.url;
                console.error(`[auth] Authorization URL: ${authorizationUrl}`);
              }
            } catch (authError) {
              console.error('[auth] Failed to generate authorization URL:', authError);
            }
          }

          return formatAuthError(error, authorizationUrl);
        }
        throw error;
      }
    };
  };
}

// ============================================================================
// Server Creation
// ============================================================================

/**
 * Creates the MCP server with authentication.
 */
function createServer(config: McpServerConfig, authManager: AuthManager): McpServer {
  const validator = authManager.getValidator();
  const withAuth = createWithAuth({ validator });
  const withErrorHandling = createErrorHandler(config, authManager);

  const server = new McpServer({
    name: 'todos-server',
    version: '0.0.1',
  });

  // -------------------------------------------------------------------------
  // Authentication Tools
  // -------------------------------------------------------------------------

  /**
   * Tool: Start authentication flow
   */
  server.registerTool(
    'auth_start',
    {
      description: 'Start OAuth authentication. Returns an authorization URL to visit.',
      inputSchema: {},
    },
    async () => {
      console.error('[auth_start] Starting authentication flow');

      const result = await authManager.startUserAuth();

      if (isAuthorizationUrlResult(result)) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  message: 'Visit the authorization URL to authenticate',
                  authorizationUrl: result.url,
                  state: result.state,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ error: 'Failed to start authentication' }, null, 2),
          },
        ],
        isError: true,
      };
    }
  );

  /**
   * Tool: Handle OAuth callback
   */
  server.registerTool(
    'auth_callback',
    {
      description: 'Exchange authorization code for tokens after OAuth callback.',
      inputSchema: {
        code: z.string().describe('The authorization code'),
        state: z.string().describe('The state parameter'),
      },
    },
    async ({ code, state }) => {
      console.error('[auth_callback] Handling callback');

      const result = await authManager.handleCallback(code, state);

      if (result.success) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  message: 'Authentication successful',
                  expiresAt: new Date(result.tokens.expiresAt).toISOString(),
                  scopes: result.tokens.scopes,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              { error: 'Authentication failed', details: result.error },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
  );

  /**
   * Tool: Get authentication status
   */
  server.registerTool(
    'auth_status',
    {
      description: 'Check current authentication status.',
      inputSchema: {},
    },
    async () => {
      const authState = await authManager.getAuthState();

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                authenticated: authState.isUserAuthenticated,
                expiresAt: authState.userTokens
                  ? new Date(authState.userTokens.expiresAt).toISOString()
                  : null,
                scopes: authState.userTokens?.scopes ?? [],
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  /**
   * Tool: Logout
   */
  server.registerTool(
    'auth_logout',
    {
      description: 'Clear stored tokens and log out.',
      inputSchema: {},
    },
    async () => {
      await authManager.logout();
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ message: 'Logged out' }, null, 2),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // Protected Todo Tools (require authentication)
  // -------------------------------------------------------------------------

  /**
   * Tool: List todos (requires authentication)
   */
  server.registerTool(
    'list_todos',
    {
      description: 'List todos. Requires authentication.',
      inputSchema: {
        userId: z.number().optional().describe('Filter by user ID (1-10)'),
        limit: z.number().optional().describe('Maximum todos to return'),
      },
    },
    withErrorHandling(
      withAuth({ requiredScopes: config.requiredUserScopes }, async ({ userId, limit }, extra) => {
        const sub = extra.authInfo?.extra?.['sub'];
        console.error(`[list_todos] User: ${String(sub)}`);

        const todos = await fetchTodos(userId);
        const limitedTodos = limit !== undefined ? todos.slice(0, limit) : todos;

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(limitedTodos, null, 2),
            },
          ],
        };
      })
    )
  );

  /**
   * Tool: Get todo by ID (requires authentication)
   */
  server.registerTool(
    'get_todo',
    {
      description: 'Get a todo by ID. Requires authentication.',
      inputSchema: {
        id: z.number().describe('Todo ID (1-200)'),
      },
    },
    withErrorHandling(
      withAuth({ requiredScopes: config.requiredUserScopes }, async ({ id }, extra) => {
        const sub = extra.authInfo?.extra?.['sub'];
        console.error(`[get_todo] User: ${String(sub)}`);

        const todo = await fetchTodoById(id);

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(todo, null, 2),
            },
          ],
        };
      })
    )
  );

  /**
   * Tool: Get todos summary (requires authentication)
   */
  server.registerTool(
    'get_todos_summary',
    {
      description: 'Get completion summary for a user. Requires authentication.',
      inputSchema: {
        userId: z.number().describe('User ID (1-10)'),
      },
    },
    withErrorHandling(
      withAuth({ requiredScopes: config.requiredUserScopes }, async ({ userId }, extra) => {
        const sub = extra.authInfo?.extra?.['sub'];
        console.error(`[get_todos_summary] User: ${String(sub)}`);

        const todos = await fetchTodos(userId);
        const completed = todos.filter((t) => t.completed).length;

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  userId,
                  total: todos.length,
                  completed,
                  pending: todos.length - completed,
                  completionRate: `${String(Math.round((completed / todos.length) * 100))}%`,
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
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  console.error('[server] Starting MCP server');

  const config = createServerConfig();
  console.error(`[server] AM URL: ${config.amUrl}`);
  console.error(`[server] Client ID: ${config.client.clientId}`);

  const authManager = createAuthManager(config);
  const server = createServer(config, authManager);
  const transport = new StdioServerTransport();

  await server.connect(transport);
  console.error('[server] Connected via stdio');

  process.on('SIGINT', () => {
    console.error('[server] Shutting down...');
    server.close().catch(console.error);
    process.exit(0);
  });
}

main().catch((error: unknown) => {
  console.error('[server] Fatal error:', error);
  process.exit(1);
});
