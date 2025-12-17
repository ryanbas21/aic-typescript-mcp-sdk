#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

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
 * Creates the MCP server with todos tools
 */
function createServer(): McpServer {
  const server = new McpServer({
    name: 'todos-server',
    version: '0.0.1',
  });

  // Tool: List all todos or filter by userId
  server.registerTool(
    'list_todos',
    {
      description: 'List todos from JSONPlaceholder API. Optionally filter by userId.',
      inputSchema: {
        userId: z.number().optional().describe('Filter todos by user ID (1-10)'),
        limit: z.number().optional().describe('Maximum number of todos to return'),
      },
    },
    async ({ userId, limit }) => {
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
    }
  );

  // Tool: Get a specific todo by ID
  server.registerTool(
    'get_todo',
    {
      description: 'Get a specific todo by its ID from JSONPlaceholder API.',
      inputSchema: {
        id: z.number().describe('The todo ID to fetch (1-200)'),
      },
    },
    async ({ id }) => {
      const todo = await fetchTodoById(id);

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(todo, null, 2),
          },
        ],
      };
    }
  );

  // Tool: Get todos summary by user
  server.registerTool(
    'get_todos_summary',
    {
      description: 'Get a summary of todos completion status for a specific user.',
      inputSchema: {
        userId: z.number().describe('The user ID to get summary for (1-10)'),
      },
    },
    async ({ userId }) => {
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
    }
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
