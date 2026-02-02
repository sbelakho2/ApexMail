/**
 * Type declarations for AWS SDK modules
 * These are stub declarations to allow dynamic imports without installing the full AWS SDK
 */

declare module '@aws-sdk/client-s3' {
  export class S3Client {
    constructor(config: any);
    send(command: any): Promise<any>;
  }

  export class PutObjectCommand {
    constructor(input: {
      Bucket: string;
      Key: string;
      Body: string | Buffer;
      ContentType?: string;
      ServerSideEncryption?: string;
      SSEKMSKeyId?: string;
    });
  }

  export class HeadBucketCommand {
    constructor(input: { Bucket: string });
  }

  export class GetObjectCommand {
    constructor(input: { Bucket: string; Key: string });
  }

  export class DeleteObjectCommand {
    constructor(input: { Bucket: string; Key: string });
  }

  export class ListObjectsV2Command {
    constructor(input: { Bucket: string; Prefix?: string; MaxKeys?: number });
  }
}

declare module '@aws-sdk/client-secrets-manager' {
  export class SecretsManagerClient {
    constructor(config: any);
    send(command: any): Promise<any>;
  }

  export class GetSecretValueCommand {
    constructor(input: { SecretId: string });
  }

  export class CreateSecretCommand {
    constructor(input: { Name: string; SecretString: string });
  }

  export class UpdateSecretCommand {
    constructor(input: { SecretId: string; SecretString: string });
  }

  export class DeleteSecretCommand {
    constructor(input: { SecretId: string });
  }
}
