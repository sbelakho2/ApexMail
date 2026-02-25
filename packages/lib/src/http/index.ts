/**
 * HTTP Client Wrapper - Thin Interface over Undici
 * 
 * Provides:
 * - Automatic retries with exponential backoff
 * - Request/response logging
 * - Timeout handling
 * - Circuit breaker pattern
 */

import { request, type Dispatcher } from 'undici';
import { Result } from '../result.js';
import { getLogger, type Logger } from '../logger/index.js';

export interface HttpRequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  headers?: Record<string, string>;
  body?: string | Buffer | Record<string, unknown>;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  maxRetryDelay?: number;
}

export interface HttpResponse<T = unknown> {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  data: T;
  latencyMs: number;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeoutMs: number;
  halfOpenRequests: number;
}

type CircuitState = 'closed' | 'open' | 'half-open';

class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failures = 0;
  private lastFailureTime = 0;
  private halfOpenSuccesses = 0;
  private readonly config: CircuitBreakerConfig;

  constructor(config: CircuitBreakerConfig) {
    this.config = config;
  }

  canRequest(): boolean {
    if (this.state === 'closed') {
      return true;
    }

    if (this.state === 'open') {
      const timeSinceFailure = Date.now() - this.lastFailureTime;
      if (timeSinceFailure >= this.config.resetTimeoutMs) {
        this.state = 'half-open';
        this.halfOpenSuccesses = 0;
        return true;
      }
      return false;
    }

    // half-open: allow limited requests
    return this.halfOpenSuccesses < this.config.halfOpenRequests;
  }

  recordSuccess(): void {
    if (this.state === 'half-open') {
      this.halfOpenSuccesses++;
      if (this.halfOpenSuccesses >= this.config.halfOpenRequests) {
        this.state = 'closed';
        this.failures = 0;
      }
    } else {
      this.failures = 0;
    }
  }

  recordFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.state === 'half-open') {
      this.state = 'open';
    } else if (this.failures >= this.config.failureThreshold) {
      this.state = 'open';
    }
  }

  getState(): CircuitState {
    return this.state;
  }
}

export class HttpClient {
  private readonly logger: Logger;
  private readonly baseUrl?: string;
  private readonly defaultHeaders: Record<string, string>;
  private readonly defaultTimeout: number;
  private readonly circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private readonly circuitBreakerConfig: CircuitBreakerConfig;
  private static readonly MAX_BREAKERS = 1000;

  constructor(options: {
    baseUrl?: string;
    defaultHeaders?: Record<string, string>;
    defaultTimeout?: number;
    circuitBreaker?: CircuitBreakerConfig;
  } = {}) {
    this.logger = getLogger().child({ component: 'http-client' });
    this.baseUrl = options.baseUrl;
    this.defaultHeaders = {
      'User-Agent': 'ApexMail/1.0',
      'Accept': 'application/json',
      ...options.defaultHeaders,
    };
    this.defaultTimeout = options.defaultTimeout ?? 30000;
    this.circuitBreakerConfig = options.circuitBreaker ?? {
      failureThreshold: 5,
      resetTimeoutMs: 30000,
      halfOpenRequests: 3,
    };
  }

  private getCircuitBreaker(host: string): CircuitBreaker {
    let breaker = this.circuitBreakers.get(host);
    if (!breaker) {
      breaker = new CircuitBreaker(this.circuitBreakerConfig);
      if (this.circuitBreakers.size >= HttpClient.MAX_BREAKERS) {
        const oldestKey = this.circuitBreakers.keys().next().value as string | undefined;
        if (oldestKey) {
          this.circuitBreakers.delete(oldestKey);
        }
      }
      this.circuitBreakers.set(host, breaker);
    } else {
      // Refresh insertion order for LRU-style eviction.
      this.circuitBreakers.delete(host);
      this.circuitBreakers.set(host, breaker);
    }
    return breaker;
  }

  async request<T = unknown>(
    url: string,
    options: HttpRequestOptions = {}
  ): Promise<Result<HttpResponse<T>, Error>> {
    const fullUrl = this.baseUrl ? new URL(url, this.baseUrl).toString() : url;
    const parsedUrl = new URL(fullUrl);
    const circuitBreaker = this.getCircuitBreaker(parsedUrl.host);

    if (!circuitBreaker.canRequest()) {
      return Result.err(new Error(`Circuit breaker open for ${parsedUrl.host}`));
    }

    const method = options.method ?? 'GET';
    const timeout = options.timeout ?? this.defaultTimeout;
    const retries = options.retries ?? 3;
    const baseRetryDelay = options.retryDelay ?? 1000;
    const maxRetryDelay = options.maxRetryDelay ?? 30000;
    const isIdempotent = ['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'].includes(method.toUpperCase());

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= retries; attempt++) {
      const startTime = Date.now();

      try {
        const headers: Record<string, string> = {
          ...this.defaultHeaders,
          ...options.headers,
        };

        let body: string | Buffer | undefined;
        if (options.body) {
          if (typeof options.body === 'object' && !Buffer.isBuffer(options.body)) {
            body = JSON.stringify(options.body);
            headers['Content-Type'] = 'application/json';
          } else {
            body = options.body as string | Buffer;
          }
        }

        const response = await request(fullUrl, {
          method: method as Dispatcher.HttpMethod,
          headers,
          body,
          headersTimeout: timeout,
          bodyTimeout: timeout,
        });

        const latencyMs = Date.now() - startTime;
        const responseHeaders: Record<string, string | string[] | undefined> = {};
        
        for (const [key, value] of Object.entries(response.headers)) {
          responseHeaders[key] = value;
        }

        const contentType = response.headers['content-type'] ?? '';
        let data: T;

        if (contentType.includes('application/json')) {
          const text = await response.body.text();
          data = JSON.parse(text) as T;
        } else {
          data = (await response.body.text()) as T;
        }

        this.logger.debug('HTTP request completed', {
          method,
          url: fullUrl,
          status: response.statusCode,
          latencyMs,
          attempt,
        });

        // Consider 5xx as failures for circuit breaker
        if (response.statusCode >= 500) {
          circuitBreaker.recordFailure();

          if (attempt < retries && isIdempotent) {
            // FIX-500-374: Add randomized jitter to prevent thundering herd
            const jitter = Math.random() * baseRetryDelay * 0.5;
            const delay = Math.min(
              baseRetryDelay * Math.pow(2, attempt) + jitter,
              maxRetryDelay
            );
            await this.sleep(delay);
            continue;
          }

          return Result.err(new Error(`HTTP ${response.statusCode} from ${fullUrl}`));
        } else {
          circuitBreaker.recordSuccess();
        }

        return Result.ok({
          status: response.statusCode,
          headers: responseHeaders,
          data,
          latencyMs,
        });
      } catch (error) {
        const latencyMs = Date.now() - startTime;
        lastError = error instanceof Error ? error : new Error(String(error));

        this.logger.warn('HTTP request failed', {
          method,
          url: fullUrl,
          error: lastError.message,
          latencyMs,
          attempt,
        });

        circuitBreaker.recordFailure();

        if (attempt < retries && isIdempotent) {
          // FIX-500-374: Add randomized jitter to prevent thundering herd
          const jitter = Math.random() * baseRetryDelay * 0.5;
          const delay = Math.min(
            baseRetryDelay * Math.pow(2, attempt) + jitter,
            maxRetryDelay
          );
          await this.sleep(delay);
        }
      }
    }

    return Result.err(lastError ?? new Error('Request failed'));
  }

  async get<T = unknown>(
    url: string,
    options?: Omit<HttpRequestOptions, 'method' | 'body'>
  ): Promise<Result<HttpResponse<T>, Error>> {
    return this.request<T>(url, { ...options, method: 'GET' });
  }

  async post<T = unknown>(
    url: string,
    body?: Record<string, unknown> | string | Buffer,
    options?: Omit<HttpRequestOptions, 'method' | 'body'>
  ): Promise<Result<HttpResponse<T>, Error>> {
    return this.request<T>(url, { ...options, method: 'POST', body });
  }

  async put<T = unknown>(
    url: string,
    body?: Record<string, unknown> | string | Buffer,
    options?: Omit<HttpRequestOptions, 'method' | 'body'>
  ): Promise<Result<HttpResponse<T>, Error>> {
    return this.request<T>(url, { ...options, method: 'PUT', body });
  }

  async delete<T = unknown>(
    url: string,
    options?: Omit<HttpRequestOptions, 'method' | 'body'>
  ): Promise<Result<HttpResponse<T>, Error>> {
    return this.request<T>(url, { ...options, method: 'DELETE' });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Default client instance
let defaultClient: HttpClient | null = null;

export function getHttpClient(): HttpClient {
  if (!defaultClient) {
    defaultClient = new HttpClient();
  }
  return defaultClient;
}

export function createHttpClient(options?: ConstructorParameters<typeof HttpClient>[0]): HttpClient {
  return new HttpClient(options);
}
