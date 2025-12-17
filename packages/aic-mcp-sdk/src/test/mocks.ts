/**
 * Mock factories for testing.
 * Provides configurable mock implementations of interfaces.
 */

import { ok, err, type Result } from 'neverthrow';
import type { HttpClient, HttpError, HttpResponse, HttpRequest } from '../http/types.js';
import type { Cache } from '../cache/types.js';

// ============================================================================
// HTTP Client Mocks
// ============================================================================

/**
 * Configuration for creating a mock HTTP client.
 */
export interface MockHttpClientConfig<T> {
  /** Response to return on success */
  readonly response?: HttpResponse<T>;
  /** Error to return on failure */
  readonly error?: HttpError;
  /** Function to capture requests for assertions */
  readonly onRequest?: (url: string, method: string) => void;
}

/**
 * Creates a mock HTTP client for testing.
 * Returns configured success/error responses.
 */
export const createMockHttpClient = <T>(config: MockHttpClientConfig<T> = {}): HttpClient => {
  const { response, error, onRequest } = config;

  const json = <TResponse>(
    request: HttpRequest
  ): Promise<Result<HttpResponse<TResponse>, HttpError>> => {
    onRequest?.(request.url, request.method);

    if (error) {
      return Promise.resolve(err(error));
    }

    if (response) {
      return Promise.resolve(ok(response as unknown as HttpResponse<TResponse>));
    }

    // Default success response
    return Promise.resolve(
      ok({
        status: 200,
        statusText: 'OK',
        headers: {},
        body: {} as TResponse,
      })
    );
  };

  const text = (request: HttpRequest): Promise<Result<HttpResponse<string>, HttpError>> => {
    onRequest?.(request.url, request.method);

    if (error) {
      return Promise.resolve(err(error));
    }

    return Promise.resolve(
      ok({
        status: 200,
        statusText: 'OK',
        headers: {},
        body: '',
      })
    );
  };

  return { json, text };
};

/**
 * Creates a mock HTTP client that returns a successful JSON response.
 */
export const createSuccessHttpClient = (body: unknown, status = 200): HttpClient =>
  createMockHttpClient({
    response: { status, statusText: 'OK', headers: {}, body },
  });

/**
 * Creates a mock HTTP client that returns an error.
 */
export const createErrorHttpClient = (
  message: string,
  status?: number,
  cause?: unknown
): HttpClient =>
  createMockHttpClient({
    error: { type: 'http', message, status, cause },
  });

/**
 * Creates a mock HTTP client that tracks requests.
 */
export const createTrackingHttpClient = (
  body: unknown,
  requests: { url: string; method: string }[]
): HttpClient =>
  createMockHttpClient({
    response: { status: 200, statusText: 'OK', headers: {}, body },
    onRequest: (url, method) => requests.push({ url, method }),
  });

// ============================================================================
// Cache Mocks
// ============================================================================

/**
 * Tracked set call for assertions.
 */
interface TrackedSetCall<T> {
  readonly key: string;
  readonly value: T;
  readonly ttlMs: number | undefined;
}

/**
 * Creates a mock cache for testing.
 * Optionally pre-populated with initial data.
 */
export const createMockCache = <T>(
  initialData?: Record<string, T>
): Cache<T> & {
  readonly data: Map<string, T>;
  readonly setCalls: TrackedSetCall<T>[];
  readonly getCalls: string[];
  readonly deleteCalls: string[];
} => {
  const data = new Map<string, T>(initialData ? Object.entries(initialData) : undefined);
  const setCalls: TrackedSetCall<T>[] = [];
  const getCalls: string[] = [];
  const deleteCalls: string[] = [];

  return {
    data,
    setCalls,
    getCalls,
    deleteCalls,

    get: (key: string): T | undefined => {
      getCalls.push(key);
      return data.get(key);
    },

    set: (key: string, value: T, ttlMs?: number): void => {
      setCalls.push({ key, value, ttlMs });
      data.set(key, value);
    },

    delete: (key: string): boolean => {
      deleteCalls.push(key);
      return data.delete(key);
    },

    clear: (): void => {
      data.clear();
    },
  };
};

// ============================================================================
// Timer Mocks
// ============================================================================

/**
 * Fake timer interface for testing time-based logic.
 */
interface FakeTimer {
  now: () => number;
  advance: (ms: number) => void;
  set: (time: number) => void;
}

/**
 * Creates a controllable fake timer for testing time-based logic.
 */
export const createFakeTimer = (initialTime = Date.now()): FakeTimer => {
  let currentTime = initialTime;

  return {
    now: (): number => currentTime,
    advance: (ms: number): void => {
      currentTime += ms;
    },
    set: (time: number): void => {
      currentTime = time;
    },
  };
};
