import { ok, err } from 'neverthrow';
import type { Result } from 'neverthrow';
import type {
  HttpClient,
  HttpClientOptions,
  HttpRequest,
  HttpResponse,
  HttpError,
} from './types.js';

/** Default request timeout: 10 seconds */
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Extracts headers from a fetch Response into a plain object.
 */
const extractHeaders = (headers: Headers): Record<string, string> => {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
};

/**
 * Creates an HTTP client using the native fetch API.
 *
 * @param options - Optional client configuration
 * @returns An HttpClient instance
 *
 * @example
 * ```typescript
 * const client = createFetchClient({ timeoutMs: 5000 });
 * const result = await client.json<User>({ url: '/api/user', method: 'GET' });
 *
 * if (result.isOk()) {
 *   console.log(result.value.body);
 * } else {
 *   console.error(result.error.message);
 * }
 * ```
 */
export const createFetchClient = (options: HttpClientOptions = {}): HttpClient => {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, baseHeaders = {} } = options;

  /**
   * Executes a fetch request with timeout and error handling.
   */
  const executeFetch = async (request: HttpRequest): Promise<Result<Response, HttpError>> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, timeoutMs);

    try {
      const fetchOptions: RequestInit = {
        method: request.method,
        headers: {
          ...baseHeaders,
          ...request.headers,
        },
        signal: controller.signal,
      };

      // Only set body if provided (exactOptionalPropertyTypes compliance)
      if (request.body !== undefined) {
        fetchOptions.body = request.body;
      }

      const response = await fetch(request.url, fetchOptions);

      clearTimeout(timeoutId);

      if (!response.ok) {
        return err({
          type: 'http',
          message: `HTTP ${String(response.status)}: ${response.statusText}`,
          status: response.status,
        });
      }

      return ok(response);
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        return err({
          type: 'timeout',
          message: `Request timed out after ${String(timeoutMs)}ms`,
          cause: error,
        });
      }

      return err({
        type: 'network',
        message: error instanceof Error ? error.message : 'Network error',
        cause: error,
      });
    }
  };

  const json = async <T>(request: HttpRequest): Promise<Result<HttpResponse<T>, HttpError>> => {
    const fetchResult = await executeFetch({
      ...request,
      headers: {
        Accept: 'application/json',
        ...(request.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...request.headers,
      },
    });

    if (fetchResult.isErr()) {
      return err(fetchResult.error);
    }

    const response = fetchResult.value;

    try {
      const body = (await response.json()) as T;
      return ok({
        status: response.status,
        statusText: response.statusText,
        headers: extractHeaders(response.headers),
        body,
      });
    } catch (error) {
      return err({
        type: 'parse',
        message: 'Failed to parse JSON response',
        status: response.status,
        cause: error,
      });
    }
  };

  const text = async (request: HttpRequest): Promise<Result<HttpResponse<string>, HttpError>> => {
    const fetchResult = await executeFetch(request);

    if (fetchResult.isErr()) {
      return err(fetchResult.error);
    }

    const response = fetchResult.value;

    try {
      const body = await response.text();
      return ok({
        status: response.status,
        statusText: response.statusText,
        headers: extractHeaders(response.headers),
        body,
      });
    } catch (error) {
      return err({
        type: 'parse',
        message: 'Failed to read response text',
        status: response.status,
        cause: error,
      });
    }
  };

  return {
    json,
    text,
  };
};
