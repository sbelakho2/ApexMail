/**
 * Error Handler Middleware
 */

import type { ErrorHandler } from 'hono';
import type { Logger } from '@apexmail/lib';
import type { AppEnv } from '../app.js';
import { ZodError } from 'zod';

export class ApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number = 400,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ApiError';
  }

  static badRequest(message: string, code = 'BAD_REQUEST', details?: Record<string, unknown>): ApiError {
    return new ApiError(code, message, 400, details);
  }

  static unauthorized(message = 'Unauthorized', code = 'UNAUTHORIZED'): ApiError {
    return new ApiError(code, message, 401);
  }

  static forbidden(message = 'Forbidden', code = 'FORBIDDEN'): ApiError {
    return new ApiError(code, message, 403);
  }

  static notFound(resource: string, code = 'NOT_FOUND'): ApiError {
    return new ApiError(code, `${resource} not found`, 404);
  }

  static conflict(message: string, code = 'CONFLICT'): ApiError {
    return new ApiError(code, message, 409);
  }

  static tooManyRequests(message = 'Rate limit exceeded', code = 'RATE_LIMITED'): ApiError {
    return new ApiError(code, message, 429);
  }

  static internal(message = 'Internal server error', code = 'INTERNAL_ERROR'): ApiError {
    return new ApiError(code, message, 500);
  }

  static serviceUnavailable(message = 'Service temporarily unavailable', code = 'SERVICE_UNAVAILABLE'): ApiError {
    return new ApiError(code, message, 503);
  }
}

export function errorHandler(logger: Logger): ErrorHandler<AppEnv> {
  return (err, c) => {
    const requestId = c.get('requestId') ?? 'unknown';

    // Handle ApiError
    if (err instanceof ApiError) {
      if (err.statusCode >= 500) {
        logger.error('Server error', {
          requestId,
          error: err.message,
          code: err.code,
          stack: err.stack,
        });
      } else {
        logger.warn('Client error', {
          requestId,
          error: err.message,
          code: err.code,
        });
      }

      return c.json({
        error: {
          code: err.code,
          message: err.message,
          ...(err.details && { details: err.details }),
        },
      }, err.statusCode as 400);
    }

    // Handle Zod validation errors
    if (err instanceof ZodError) {
      const details = err.errors.map((e) => ({
        path: e.path.join('.'),
        message: e.message,
        code: e.code,
      }));

      logger.warn('Validation error', {
        requestId,
        errors: details,
      });

      return c.json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
          details,
        },
      }, 400);
    }

    // Handle unknown errors
    logger.error('Unhandled error', {
      requestId,
      error: err.message,
      stack: err.stack,
      name: err.name,
    });

    return c.json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      },
    }, 500);
  };
}
