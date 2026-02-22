/**
 * Ambient type declarations for dynamically-imported modules.
 *
 * @aws-sdk/client-ses is listed in package.json but only loaded at runtime
 * when EMAIL_TRANSPORT=ses. These declarations satisfy the TypeScript
 * compiler without requiring the SDK to be installed during development.
 *
 * nodemailer/lib/mail-composer is an internal Nodemailer subpath that
 * has no published @types entry. We only use it for MIME assembly in
 * the SES transport path.
 */

declare module '@aws-sdk/client-ses' {
  export class SESClient {
    constructor(config: Record<string, unknown>);
    send(command: unknown): Promise<Record<string, unknown> & { MessageId?: string }>;
    destroy(): void;
  }
  export class SendRawEmailCommand {
    constructor(params: Record<string, unknown>);
  }
  export class GetAccountCommand {
    constructor(params: Record<string, unknown>);
  }
}

declare module 'nodemailer/lib/mail-composer' {
  export class MailComposer {
    constructor(options: Record<string, unknown>);
    compile(): {
      build(callback: (err: Error | null, message: Buffer) => void): void;
    };
  }
}
