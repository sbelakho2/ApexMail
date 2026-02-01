/**
 * Result type for explicit error handling without exceptions
 * Inspired by Rust's Result<T, E> type
 */

export type Result<T, E = Error> = 
  | { ok: true; value: T }
  | { ok: false; error: E };

export const Result = {
  ok<T>(value: T): Result<T, never> {
    return { ok: true, value };
  },

  err<E>(error: E): Result<never, E> {
    return { ok: false, error };
  },

  isOk<T, E>(result: Result<T, E>): result is { ok: true; value: T } {
    return result.ok;
  },

  isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E } {
    return !result.ok;
  },

  unwrap<T, E>(result: Result<T, E>): T {
    if (result.ok) {
      return result.value;
    }
    throw result.error instanceof Error 
      ? result.error 
      : new Error(String(result.error));
  },

  unwrapOr<T, E>(result: Result<T, E>, defaultValue: T): T {
    return result.ok ? result.value : defaultValue;
  },

  map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
    if (result.ok) {
      return Result.ok(fn(result.value));
    }
    return result;
  },

  mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
    if (!result.ok) {
      return Result.err(fn(result.error));
    }
    return result;
  },

  async fromPromise<T>(promise: Promise<T>): Promise<Result<T, Error>> {
    try {
      const value = await promise;
      return Result.ok(value);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  },

  fromThrowable<T>(fn: () => T): Result<T, Error> {
    try {
      return Result.ok(fn());
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  },
};

/**
 * Option type for explicit null handling
 */
export type Option<T> = T | null;

export const Option = {
  some<T>(value: T): Option<T> {
    return value;
  },

  none<T>(): Option<T> {
    return null;
  },

  isSome<T>(option: Option<T>): option is T {
    return option !== null;
  },

  isNone<T>(option: Option<T>): option is null {
    return option === null;
  },

  unwrap<T>(option: Option<T>): T {
    if (option === null) {
      throw new Error('Attempted to unwrap None value');
    }
    return option;
  },

  unwrapOr<T>(option: Option<T>, defaultValue: T): T {
    return option ?? defaultValue;
  },

  map<T, U>(option: Option<T>, fn: (value: T) => U): Option<U> {
    return option !== null ? fn(option) : null;
  },
};

/**
 * Convenience functions for creating Result values
 */
export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

/**
 * Type guard helpers
 */
export function isOk<T, E>(result: Result<T, E>): result is { ok: true; value: T } {
  return result.ok;
}

export function isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E } {
  return !result.ok;
}
