declare module '@grpc/grpc-js' {
  export interface ServiceError extends Error {
    code?: number;
    details?: string;
    metadata?: unknown;
  }

  export class Client {
    constructor(...args: unknown[]);
    close(): void;
    waitForReady(deadline: Date, callback: (err?: Error) => void): void;
  }

  export interface ChannelCredentials {}

  export const credentials: {
    createSsl(): ChannelCredentials;
    createInsecure(): ChannelCredentials;
  };

  export interface GrpcObject {
    [key: string]: unknown;
  }

  export function loadPackageDefinition(packageDef: unknown): GrpcObject;
}

declare module '@grpc/proto-loader' {
  export interface PackageDefinition {
    [key: string]: unknown;
  }

  export interface Options {
    keepCase?: boolean;
    longs?: unknown;
    enums?: unknown;
    defaults?: boolean;
    oneofs?: boolean;
  }

  export function loadSync(filename: string, options?: Options): PackageDefinition;
}
