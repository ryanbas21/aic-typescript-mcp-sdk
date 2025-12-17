#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  createTokenValidator,
  createWithAuth,
  AuthenticationError,
  AuthorizationError,
} from '@pingidentity/aic-mcp-sdk';

/**
 * Todo item from JSONPlaceholder API
 */
interface Todo {
  readonly userId: number;
  readonly id: number;
  readonly title: string;
  readonly completed: boolean;
}

const TYPICODE_BASE_URL = 'https://jsonplaceholder.typicode.com';

/**
 * Gets configuration from environment variables.
 */
function getConfig(): { amUrl: string; clientId: string } {
  const amUrl = process.env['AM_URL'];
  const clientId = process.env['AM_CLIENT_ID'];

  if (amUrl === undefined || amUrl.length === 0) {
    throw new Error('AM_URL environment variable is required');
  }

  if (clientId === undefined || clientId.length === 0) {
    throw new Error('AM_CLIENT_ID environment variable is required');
  }

  return { amUrl, clientId };
}

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

/**
 * Formats an auth error for MCP response.
 */
function formatAuthError(error: AuthenticationError | AuthorizationError): {
  content: [{ type: 'text'; text: string }];
  isError: true;
} {
  if (error instanceof AuthorizationError) {
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              error: 'authorization_error',
              message: error.message,
              requiredScopes: error.requiredScopes,
              presentScopes: error.presentScopes,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }

  // AuthenticationError
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(
          {
            error: error.code,
            message: error.message,
            authenticationInfo: error.authenticationInfo,
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
 * Wraps a tool handler to catch auth errors and return them as MCP error responses.
 */
function withErrorHandling<TArgs, TExtra, TResult>(
  handler: (args: TArgs, extra: TExtra) => TResult | Promise<TResult>
): (args: TArgs, extra: TExtra) => Promise<TResult | ReturnType<typeof formatAuthError>> {
  return async (args: TArgs, extra: TExtra) => {
    try {
      return await handler(args, extra);
    } catch (error) {
      if (error instanceof AuthenticationError || error instanceof AuthorizationError) {
        return formatAuthError(error);
      }
      throw error;
    }
  };
}

/**
 * Creates the MCP server with todos tools protected by authentication.
 */
function createServer(): McpServer {
  const config = getConfig();

  // Create the token validator
  const validator = createTokenValidator({
    amUrl: config.amUrl,
    clientId: config.clientId,
  });

  // Create the withAuth wrapper
  const withAuth = createWithAuth({ validator });

  const server = new McpServer({
    name: 'todos-server',
    version: '0.0.1',
  });

  // Tool: List all todos or filter by userId (requires 'todos:read' scope)
  server.registerTool(
    'list_todos',
    {
      description: 'List todos from JSONPlaceholder API. Optionally filter by userId.',
      inputSchema: {
        userId: z.number().optional().describe('Filter todos by user ID (1-10)'),
        limit: z.number().optional().describe('Maximum number of todos to return'),
      },
    },
    withErrorHandling(
      withAuth({ requiredScopes: ['todos:read'] }, async ({ userId, limit }, extra) => {
        // Access authenticated user info
        const sub = extra.authInfo?.extra?.['sub'];
        console.error(`[list_todos] Authenticated user: ${String(sub)}`);

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

  // Tool: Get a specific todo by ID (requires 'todos:read' scope)
  server.registerTool(
    'get_todo',
    {
      description: 'Get a specific todo by its ID from JSONPlaceholder API.',
      inputSchema: {
        id: z.number().describe('The todo ID to fetch (1-200)'),
      },
    },
    withErrorHandling(
      withAuth({ requiredScopes: ['todos:read'] }, async ({ id }, extra) => {
        const sub = extra.authInfo?.extra?.['sub'];
        console.error(`[get_todo] Authenticated user: ${String(sub)}`);

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

  // Tool: Get todos summary by user (requires 'todos:read' scope)
  server.registerTool(
    'get_todos_summary',
    {
      description: 'Get a summary of todos completion status for a specific user.',
      inputSchema: {
        userId: z.number().describe('The user ID to get summary for (1-10)'),
      },
    },
    withErrorHandling(
      withAuth({ requiredScopes: ['todos:read'] }, async ({ userId }, extra) => {
        const sub = extra.authInfo?.extra?.['sub'];
        console.error(`[get_todos_summary] Authenticated user: ${String(sub)}`);

        const todos = await fetchTodos(userId);
        const completed = todos.filter((t) => t.completed).length;
        const pending = todos.length - completed;

        const summary = {
          userId,
          totalTodos: todos.length,
          completed,
          pending,
          completionRate: `${String(Math.round((completed / todos.length) * 100))}%`,
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(summary, null, 2),
            },
          ],
        };
      })
    )
  );

  return server;
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    server.close().catch((error: unknown) => {
      console.error('Error closing server:', error);
    });
    process.exit(0);
  });
}

main().catch((error: unknown) => {
  console.error('Server error:', error);
  process.exit(1);
});
