declare module 'ioredis' {
  export interface RedisOptions {
    host?: string;
    port?: number;
    password?: string;
    db?: number;
    keyPrefix?: string;
    maxRetriesPerRequest?: number;
    lazyConnect?: boolean;
    enableReadyCheck?: boolean;
    retryStrategy?: (times: number) => number | null | undefined;
  }

  export class Redis {
    constructor(url: string, options?: RedisOptions);
    constructor(options?: RedisOptions);
    on(event: string, listener: (...args: unknown[]) => void): this;
    connect(): Promise<void>;
    ping(): Promise<string>;
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ...args: unknown[]): Promise<'OK' | null>;
    setex(key: string, seconds: number, value: string): Promise<'OK' | null>;
    del(...keys: string[]): Promise<number>;
    smembers(key: string): Promise<string[]>;
    sadd(key: string, ...members: string[]): Promise<number>;
    incr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
    quit(): Promise<'OK' | string>;
  }

  export default Redis;
}