import type { Result } from 'neverthrow';

/**
 * HTTP request configuration.
 */
export interface HttpRequest {
  readonly url: string;
  readonly method: 'GET' | 'POST';
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
}

/**
 * HTTP response with typed body.
 */
export interface HttpResponse<T> {
  readonly status: number;
  readonly statusText: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: T;
}

/**
 * HTTP error with status and message.
 */
export interface HttpError {
  readonly type: 'network' | 'timeout' | 'parse' | 'http';
  readonly message: string;
  readonly status?: number;
  readonly cause?: unknown;
}

/**
 * HTTP client interface for making requests.
 * Abstraction over fetch for dependency injection and testing.
 */
export interface HttpClient {
  /**
   * Makes an HTTP request and parses JSON response.
   * @param request - The request configuration
   * @returns Result with parsed response or error
   */
  readonly json: <T>(request: HttpRequest) => Promise<Result<HttpResponse<T>, HttpError>>;

  /**
   * Makes an HTTP request and returns raw text response.
   * @param request - The request configuration
   * @returns Result with text response or error
   */
  readonly text: (request: HttpRequest) => Promise<Result<HttpResponse<string>, HttpError>>;
}

/**
 * Options for creating an HTTP client.
 */
export interface HttpClientOptions {
  /** Request timeout in milliseconds (default: 10000) */
  readonly timeoutMs?: number;
  /** Base headers to include in all requests */
  readonly baseHeaders?: Readonly<Record<string, string>>;
}
