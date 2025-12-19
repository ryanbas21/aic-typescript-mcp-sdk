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
import http from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { createWithAuth, AuthenticationError, AuthorizationError } from '@pingidentity/aic-mcp-sdk';
import { createServerConfig, type McpServerConfig } from './config.js';
import { createAuthManager, isAuthorizationUrlResult, type AuthManager } from './auth.js';

// ============================================================================
// OAuth Callback Server
// ============================================================================

/** Pending auth callback resolver (for blocking wait, if needed) */
let pendingAuthResolve: ((result: { code: string; state: string }) => void) | undefined;

/** Last completed auth result (for non-blocking polling) */
let lastAuthResult: { code: string; state: string } | undefined;

/**
 * Starts a minimal HTTP server to capture OAuth callbacks.
 * Listens on port 3000 for /oauth/callback redirects.
 */
function startCallbackServer(): void {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1:3000');

    if (url.pathname === '/oauth/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (code !== null && state !== null) {
        // Store result for polling
        lastAuthResult = { code, state };

        // Resolve any pending promise
        if (pendingAuthResolve !== undefined) {
          pendingAuthResolve({ code, state });
          pendingAuthResolve = undefined;
        }

        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(
          '<html><body style="font-family: system-ui; padding: 40px; text-align: center;">' +
            '<h1>✓ Authentication Successful!</h1>' +
            '<p>You can close this window and return to your IDE.</p>' +
            '</body></html>'
        );
      } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(
          '<html><body style="font-family: system-ui; padding: 40px; text-align: center;">' +
            '<h1>✗ Error</h1>' +
            '<p>Missing code or state parameter, or no pending authentication.</p>' +
            '</body></html>'
        );
      }
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error('[callback-server] Port 3000 already in use - callback server disabled');
    } else {
      console.error('[callback-server] Failed to start:', err.message);
    }
  });

  server.listen(3000, '127.0.0.1', () => {
    console.error('[callback-server] Listening on http://127.0.0.1:3000');
  });
}

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

/** Cached access token for sync extraction */
let cachedAccessToken: string | undefined;

/**
 * Updates the cached access token from auth manager.
 * Called after successful authentication.
 */
async function updateCachedToken(authManager: AuthManager): Promise<void> {
  cachedAccessToken = await authManager.getAccessToken();
}

/**
 * Creates the MCP server with authentication.
 */
function createServer(config: McpServerConfig, authManager: AuthManager): McpServer {
  const validator = authManager.getValidator();

  // Custom token extractor that pulls from stored tokens
  const withAuth = createWithAuth({
    validator,
    tokenExtractor: {
      stdioTokenSource: () => cachedAccessToken,
    },
  });

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
   * Returns authorization URL immediately. Use auth_complete after browser login.
   */
  server.registerTool(
    'auth_start',
    {
      description:
        'Start OAuth authentication. Returns a URL to open in browser. After logging in, call auth_complete to finish.',
      inputSchema: {},
    },
    async () => {
      console.error('[auth_start] Starting authentication flow');

      // Clear any previous auth result
      lastAuthResult = undefined;

      const result = await authManager.startUserAuth();

      if (!isAuthorizationUrlResult(result)) {
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

      console.error(`[auth_start] Authorization URL: ${result.url}`);

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                message:
                  'Open this URL in your browser to authenticate. After logging in, call auth_complete.',
                authorizationUrl: result.url,
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
   * Tool: Complete authentication after browser login
   * Checks for OAuth callback and exchanges code for tokens.
   */
  server.registerTool(
    'auth_complete',
    {
      description:
        'Complete authentication after browser login. Call this after visiting the auth URL.',
      inputSchema: {},
    },
    async () => {
      console.error('[auth_complete] Checking for OAuth callback...');

      if (lastAuthResult === undefined) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  status: 'waiting',
                  message: 'No callback received yet. Please complete the login in your browser.',
                },
                null,
                2
              ),
            },
          ],
        };
      }

      const { code, state } = lastAuthResult;
      console.error('[auth_complete] Callback received, exchanging code for tokens...');

      // Exchange code for tokens
      const tokenResult = await authManager.handleCallback(code, state);

      // Clear the stored result
      lastAuthResult = undefined;

      if (tokenResult.success) {
        console.error('[auth_complete] Authentication successful!');

        // Update cached token for withAuth to use
        await updateCachedToken(authManager);

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  status: 'success',
                  message: 'Authentication successful!',
                  expiresAt: new Date(tokenResult.tokens.expiresAt).toISOString(),
                  scopes: tokenResult.tokens.scopes,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      console.error('[auth_complete] Token exchange failed:', tokenResult.error);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              { status: 'error', error: 'Token exchange failed', details: tokenResult.error },
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
        // Update cached token for withAuth to use
        await updateCachedToken(authManager);

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

  // Start callback server for OAuth redirects
  startCallbackServer();

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
