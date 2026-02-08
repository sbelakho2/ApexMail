/**
 * Migration Hub Generator
 *
 * Generates static migration pages from YAML config:
 *   • /migrate/from-{provider} landing pages
 *   • 1:1 API mapping tables
 *   • Code snippets (before/after)
 *   • Gotchas + safe defaults
 *   • Auto-generated SDK examples per framework
 *
 * Design: Pages are generated at build time from YAML definitions,
 * deployed as static Next.js pages. Captures high-intent search traffic
 * from developers frustrated with existing providers.
 */

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface MigrationProvider {
  slug: string;
  name: string;
  description: string;
  estimatedTime: string;
  difficulty: 'easy' | 'moderate' | 'advanced';
  apiMappings: ApiMapping[];
  envMappings: EnvMapping[];
  codeSnippets: CodeSnippet[];
  gotchas: Gotcha[];
  sdkExamples: SdkExample[];
}

export interface ApiMapping {
  category: string;
  providerEndpoint: string;
  providerMethod: string;
  apexmailEndpoint: string;
  apexmailMethod: string;
  notes: string;
}

export interface EnvMapping {
  providerVar: string;
  apexmailVar: string;
  description: string;
}

export interface CodeSnippet {
  title: string;
  language: string;
  before: string;
  after: string;
  explanation: string;
}

export interface Gotcha {
  title: string;
  description: string;
  solution: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface SdkExample {
  framework: string;
  language: string;
  installCommand: string;
  code: string;
  description: string;
}

// ────────────────────────────────────────────────────────────────────
// Provider Definitions
// ────────────────────────────────────────────────────────────────────

export const MIGRATION_PROVIDERS: MigrationProvider[] = [
  {
    slug: 'sendgrid',
    name: 'SendGrid',
    description: 'Migrate from SendGrid to ApexMail with near-zero downtime. Most customers complete the switch in under 30 minutes.',
    estimatedTime: '30 minutes',
    difficulty: 'easy',
    apiMappings: [
      {
        category: 'Send Email',
        providerEndpoint: 'POST /v3/mail/send',
        providerMethod: 'sgMail.send(msg)',
        apexmailEndpoint: 'POST /v1/messages',
        apexmailMethod: 'apexmail.messages.send(msg)',
        notes: 'Direct 1:1 mapping. ApexMail accepts similar payload structure.',
      },
      {
        category: 'Templates',
        providerEndpoint: 'POST /v3/templates',
        providerMethod: 'sgClient.request()',
        apexmailEndpoint: 'POST /v1/templates',
        apexmailMethod: 'apexmail.templates.create()',
        notes: 'Template syntax is compatible. Handlebars-style variables work in both.',
      },
      {
        category: 'Webhooks',
        providerEndpoint: 'Event Webhook',
        providerMethod: 'Webhook URL config',
        apexmailEndpoint: 'POST /v1/webhooks',
        apexmailMethod: 'apexmail.webhooks.create()',
        notes: 'ApexMail webhooks include cryptographic signatures by default.',
      },
      {
        category: 'Domain Auth',
        providerEndpoint: 'POST /v3/whitelabel/domains',
        providerMethod: 'DNS records',
        apexmailEndpoint: 'POST /v1/domains',
        apexmailMethod: 'apexmail.domains.add()',
        notes: 'ApexMail provides exact DNS records to add. Verification is automatic.',
      },
      {
        category: 'Suppression Lists',
        providerEndpoint: 'GET /v3/suppression/bounces',
        providerMethod: 'sgClient.request()',
        apexmailEndpoint: 'GET /v1/suppressions',
        apexmailMethod: 'apexmail.suppressions.list()',
        notes: 'Import your suppression list to ApexMail to maintain deliverability.',
      },
    ],
    envMappings: [
      { providerVar: 'SENDGRID_API_KEY', apexmailVar: 'APEXMAIL_API_KEY', description: 'API authentication key' },
      { providerVar: 'SENDGRID_FROM_EMAIL', apexmailVar: 'APEXMAIL_FROM_EMAIL', description: 'Default sender address' },
      { providerVar: 'SENDGRID_TEMPLATE_ID', apexmailVar: 'APEXMAIL_TEMPLATE_ID', description: 'Template identifier' },
    ],
    codeSnippets: [
      {
        title: 'Send a transactional email',
        language: 'typescript',
        before: `import sgMail from '@sendgrid/mail';

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

await sgMail.send({
  to: 'user@example.com',
  from: 'team@yourapp.com',
  subject: 'Welcome to YourApp',
  html: '<h1>Welcome!</h1><p>Thanks for signing up.</p>',
});`,
        after: `import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY);

await apexmail.messages.send({
  to: 'user@example.com',
  from: 'team@yourapp.com',
  subject: 'Welcome to YourApp',
  html: '<h1>Welcome!</h1><p>Thanks for signing up.</p>',
});`,
        explanation: 'The API is nearly identical. Replace the import and initialization — the send payload structure stays the same.',
      },
      {
        title: 'Verify webhook signature',
        language: 'typescript',
        before: `import { EventWebhook } from '@sendgrid/eventwebhook';

const ew = new EventWebhook();
const publicKey = ew.convertPublicKeyToECDSA(VERIFICATION_KEY);
const valid = ew.verifySignature(
  publicKey, payload, signature, timestamp
);`,
        after: `import { verifyWebhook } from '@apexmail/node';

const valid = verifyWebhook({
  payload: req.body,
  signature: req.headers['x-apexmail-signature'],
  secret: process.env.APEXMAIL_WEBHOOK_SECRET,
});`,
        explanation: 'ApexMail uses HMAC-SHA256 signatures. Simpler API — no key conversion step needed.',
      },
    ],
    gotchas: [
      {
        title: 'Import your suppression list first',
        description: 'SendGrid maintains bounces and unsubscribes separately. Export both before migrating.',
        solution: 'Use the ApexMail CLI: `apexmail suppressions import --file bounces.csv`',
        severity: 'critical',
      },
      {
        title: 'DNS propagation takes time',
        description: 'After adding ApexMail DNS records, allow up to 48 hours for propagation.',
        solution: 'Run both providers in parallel during DNS propagation. ApexMail auto-verifies when records resolve.',
        severity: 'warning',
      },
      {
        title: 'Template variable syntax',
        description: 'SendGrid uses {{variable}} and ApexMail also uses {{variable}} — no changes needed.',
        solution: 'Templates work as-is. Just update the template ID in your code.',
        severity: 'info',
      },
    ],
    sdkExamples: [],
  },
  {
    slug: 'resend',
    name: 'Resend',
    description: 'Switch from Resend to ApexMail for better compliance, self-hosting options, and enterprise features.',
    estimatedTime: '15 minutes',
    difficulty: 'easy',
    apiMappings: [
      {
        category: 'Send Email',
        providerEndpoint: 'POST /emails',
        providerMethod: 'resend.emails.send()',
        apexmailEndpoint: 'POST /v1/messages',
        apexmailMethod: 'apexmail.messages.send()',
        notes: 'Nearly identical API structure.',
      },
      {
        category: 'Domains',
        providerEndpoint: 'POST /domains',
        providerMethod: 'resend.domains.create()',
        apexmailEndpoint: 'POST /v1/domains',
        apexmailMethod: 'apexmail.domains.add()',
        notes: 'Same flow: add domain, configure DNS, verify.',
      },
      {
        category: 'API Keys',
        providerEndpoint: 'POST /api-keys',
        providerMethod: 'resend.apiKeys.create()',
        apexmailEndpoint: 'POST /v1/api-keys',
        apexmailMethod: 'apexmail.apiKeys.create()',
        notes: 'ApexMail supports scoped permissions per API key.',
      },
    ],
    envMappings: [
      { providerVar: 'RESEND_API_KEY', apexmailVar: 'APEXMAIL_API_KEY', description: 'API authentication key' },
    ],
    codeSnippets: [
      {
        title: 'Send email (TypeScript)',
        language: 'typescript',
        before: `import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

await resend.emails.send({
  from: 'team@yourapp.com',
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Welcome!</p>',
});`,
        after: `import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY);

await apexmail.messages.send({
  from: 'team@yourapp.com',
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Welcome!</p>',
});`,
        explanation: 'The SDK interface is almost identical. Replace the import and class name.',
      },
    ],
    gotchas: [
      {
        title: 'Webhook format differences',
        description: 'Resend webhooks use a different event naming convention.',
        solution: 'ApexMail uses standardized event names: email.delivered, email.bounced, etc. Update your webhook handler mapping.',
        severity: 'warning',
      },
    ],
    sdkExamples: [],
  },
  {
    slug: 'amazon-ses',
    name: 'Amazon SES',
    description: 'Move from AWS SES to ApexMail for a developer-friendly API, built-in compliance, and no infrastructure management.',
    estimatedTime: '45 minutes',
    difficulty: 'moderate',
    apiMappings: [
      {
        category: 'Send Email',
        providerEndpoint: 'SendEmail / SendRawEmail',
        providerMethod: 'ses.sendEmail(params)',
        apexmailEndpoint: 'POST /v1/messages',
        apexmailMethod: 'apexmail.messages.send()',
        notes: 'ApexMail simplifies the verbose SES API into a clean REST call.',
      },
      {
        category: 'Templates',
        providerEndpoint: 'CreateTemplate',
        providerMethod: 'ses.createTemplate(params)',
        apexmailEndpoint: 'POST /v1/templates',
        apexmailMethod: 'apexmail.templates.create()',
        notes: 'No more JSON template definitions. Use the visual editor or API.',
      },
      {
        category: 'Notifications',
        providerEndpoint: 'SNS Topics',
        providerMethod: 'SNS subscription',
        apexmailEndpoint: 'POST /v1/webhooks',
        apexmailMethod: 'apexmail.webhooks.create()',
        notes: 'Direct webhooks replace the SNS → SQS → Lambda chain.',
      },
    ],
    envMappings: [
      { providerVar: 'AWS_ACCESS_KEY_ID', apexmailVar: 'APEXMAIL_API_KEY', description: 'Authentication' },
      { providerVar: 'AWS_SECRET_ACCESS_KEY', apexmailVar: '(not needed)', description: 'ApexMail uses a single API key' },
      { providerVar: 'AWS_REGION', apexmailVar: 'APEXMAIL_REGION', description: 'Data region (EU or US)' },
    ],
    codeSnippets: [
      {
        title: 'Send email (Node.js)',
        language: 'typescript',
        before: `import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';

const ses = new SESClient({ region: 'us-east-1' });

await ses.send(new SendEmailCommand({
  Source: 'team@yourapp.com',
  Destination: { ToAddresses: ['user@example.com'] },
  Message: {
    Subject: { Data: 'Hello' },
    Body: { Html: { Data: '<p>Welcome!</p>' } },
  },
}));`,
        after: `import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY);

await apexmail.messages.send({
  from: 'team@yourapp.com',
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Welcome!</p>',
});`,
        explanation: 'Dramatically simpler. No AWS SDK boilerplate, no region config, no nested message structures.',
      },
    ],
    gotchas: [
      {
        title: 'SES sending limits don\'t transfer',
        description: 'Your SES sending quota is tied to your AWS account. You\'ll start fresh with ApexMail.',
        solution: 'ApexMail auto-warms your sending reputation. Start with low volume and scale up over 2 weeks.',
        severity: 'warning',
      },
      {
        title: 'SNS notification → webhook migration',
        description: 'SES uses SNS topics for bounce/complaint notifications. ApexMail uses direct webhooks.',
        solution: 'Set up ApexMail webhooks for the same events. You can remove the SNS → SQS → Lambda pipeline.',
        severity: 'warning',
      },
    ],
    sdkExamples: [],
  },
  {
    slug: 'postmark',
    name: 'Postmark',
    description: 'Migrate from Postmark to ApexMail for self-hosting, advanced compliance tools, and transparent pricing.',
    estimatedTime: '20 minutes',
    difficulty: 'easy',
    apiMappings: [
      {
        category: 'Send Email',
        providerEndpoint: 'POST /email',
        providerMethod: 'client.sendEmail()',
        apexmailEndpoint: 'POST /v1/messages',
        apexmailMethod: 'apexmail.messages.send()',
        notes: 'Similar REST API structure.',
      },
      {
        category: 'Templates',
        providerEndpoint: 'POST /templates',
        providerMethod: 'client.createTemplate()',
        apexmailEndpoint: 'POST /v1/templates',
        apexmailMethod: 'apexmail.templates.create()',
        notes: 'Template variables use the same {{variable}} syntax.',
      },
      {
        category: 'Message Streams',
        providerEndpoint: 'Transactional / Broadcast streams',
        providerMethod: 'MessageStream config',
        apexmailEndpoint: 'Traffic type headers',
        apexmailMethod: 'X-ApexMail-Traffic-Type header',
        notes: 'ApexMail isolates traffic types automatically via header classification.',
      },
    ],
    envMappings: [
      { providerVar: 'POSTMARK_SERVER_TOKEN', apexmailVar: 'APEXMAIL_API_KEY', description: 'API authentication' },
      { providerVar: 'POSTMARK_ACCOUNT_TOKEN', apexmailVar: '(not needed)', description: 'ApexMail uses a single key model' },
    ],
    codeSnippets: [
      {
        title: 'Send transactional email',
        language: 'typescript',
        before: `import { ServerClient } from 'postmark';

const client = new ServerClient(process.env.POSTMARK_SERVER_TOKEN);

await client.sendEmail({
  From: 'team@yourapp.com',
  To: 'user@example.com',
  Subject: 'Hello',
  HtmlBody: '<p>Welcome!</p>',
  MessageStream: 'outbound',
});`,
        after: `import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY);

await apexmail.messages.send({
  from: 'team@yourapp.com',
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Welcome!</p>',
});`,
        explanation: 'Replace the Postmark client with ApexMail. The payload is simpler — no MessageStream needed.',
      },
    ],
    gotchas: [
      {
        title: 'Postmark uses PascalCase, ApexMail uses camelCase',
        description: 'API field names differ in casing convention.',
        solution: 'Use the ApexMail SDK which handles serialization. Or update field names: From → from, To → to, etc.',
        severity: 'info',
      },
    ],
    sdkExamples: [],
  },
  {
    slug: 'mailgun',
    name: 'Mailgun',
    description: 'Switch from Mailgun to ApexMail for consistent deliverability, transparent pricing, and no surprise charges.',
    estimatedTime: '30 minutes',
    difficulty: 'easy',
    apiMappings: [
      {
        category: 'Send Email',
        providerEndpoint: 'POST /{domain}/messages',
        providerMethod: 'mg.messages.create()',
        apexmailEndpoint: 'POST /v1/messages',
        apexmailMethod: 'apexmail.messages.send()',
        notes: 'No domain scoping needed in ApexMail URL. Domain is inferred from the From address.',
      },
      {
        category: 'Webhooks',
        providerEndpoint: 'Webhook URLs in dashboard',
        providerMethod: 'Dashboard config',
        apexmailEndpoint: 'POST /v1/webhooks',
        apexmailMethod: 'apexmail.webhooks.create()',
        notes: 'Programmatic webhook management. No dashboard required.',
      },
    ],
    envMappings: [
      { providerVar: 'MAILGUN_API_KEY', apexmailVar: 'APEXMAIL_API_KEY', description: 'API authentication' },
      { providerVar: 'MAILGUN_DOMAIN', apexmailVar: '(auto-detected)', description: 'Inferred from sender address in ApexMail' },
    ],
    codeSnippets: [
      {
        title: 'Send email',
        language: 'typescript',
        before: `import Mailgun from 'mailgun.js';
import formData from 'form-data';

const mg = new Mailgun(formData).client({
  username: 'api',
  key: process.env.MAILGUN_API_KEY,
});

await mg.messages.create(process.env.MAILGUN_DOMAIN, {
  from: 'team@yourapp.com',
  to: ['user@example.com'],
  subject: 'Hello',
  html: '<p>Welcome!</p>',
});`,
        after: `import { ApexMail } from '@apexmail/node';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY);

await apexmail.messages.send({
  from: 'team@yourapp.com',
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Welcome!</p>',
});`,
        explanation: 'No form-data dependency needed. No domain parameter in the URL. Cleaner SDK.',
      },
    ],
    gotchas: [
      {
        title: 'Mailgun EU vs US regions',
        description: 'If you use Mailgun EU, make sure to configure ApexMail for EU data residency.',
        solution: 'Set APEXMAIL_REGION=eu when initializing the client.',
        severity: 'warning',
      },
    ],
    sdkExamples: [],
  },
];

// ────────────────────────────────────────────────────────────────────
// SDK Examples (shared across providers)
// ────────────────────────────────────────────────────────────────────

export const FRAMEWORK_SDK_EXAMPLES: SdkExample[] = [
  {
    framework: 'Next.js',
    language: 'typescript',
    installCommand: 'npm install @apexmail/node',
    description: 'Send transactional email from a Next.js API route or Server Action.',
    code: `// app/api/send/route.ts
import { ApexMail } from '@apexmail/node';
import { NextResponse } from 'next/server';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY!);

export async function POST(req: Request) {
  const { to, subject, html } = await req.json();

  const result = await apexmail.messages.send({
    from: 'team@yourapp.com',
    to,
    subject,
    html,
  });

  return NextResponse.json({ messageId: result.id });
}`,
  },
  {
    framework: 'Laravel',
    language: 'php',
    installCommand: 'composer require apexmail/apexmail-php',
    description: 'Configure ApexMail as a Laravel mail transport.',
    code: `// config/mail.php
'mailers' => [
    'apexmail' => [
        'transport' => 'apexmail',
        'key' => env('APEXMAIL_API_KEY'),
    ],
],

// Usage in a Controller:
use Illuminate\\Support\\Facades\\Mail;
use App\\Mail\\WelcomeEmail;

Mail::mailer('apexmail')->to($user)->send(new WelcomeEmail());`,
  },
  {
    framework: 'Rails',
    language: 'ruby',
    installCommand: 'gem install apexmail',
    description: 'Use ApexMail as your Action Mailer delivery method.',
    code: `# config/environments/production.rb
config.action_mailer.delivery_method = :apexmail
config.action_mailer.apexmail_settings = {
  api_key: ENV['APEXMAIL_API_KEY']
}

# app/mailers/user_mailer.rb
class UserMailer < ApplicationMailer
  def welcome_email(user)
    mail(to: user.email, subject: 'Welcome!')
  end
end`,
  },
  {
    framework: 'Django',
    language: 'python',
    installCommand: 'pip install apexmail-python',
    description: 'Send email from Django using the ApexMail Python SDK.',
    code: `# settings.py
APEXMAIL_API_KEY = os.environ.get('APEXMAIL_API_KEY')

# views.py
from apexmail import ApexMail

client = ApexMail(api_key=settings.APEXMAIL_API_KEY)

result = client.messages.send(
    from_email='team@yourapp.com',
    to='user@example.com',
    subject='Welcome!',
    html='<p>Welcome to our platform!</p>',
)`,
  },
  {
    framework: 'Go Fiber',
    language: 'go',
    installCommand: 'go get github.com/apexmail/apexmail-go',
    description: 'Send email from a Go Fiber API handler.',
    code: `package main

import (
    "github.com/apexmail/apexmail-go"
    "github.com/gofiber/fiber/v2"
    "os"
)

func main() {
    client := apexmail.NewClient(os.Getenv("APEXMAIL_API_KEY"))
    app := fiber.New()

    app.Post("/send", func(c *fiber.Ctx) error {
        result, err := client.Messages.Send(&apexmail.SendParams{
            From:    "team@yourapp.com",
            To:      "user@example.com",
            Subject: "Welcome!",
            HTML:    "<p>Welcome!</p>",
        })
        if err != nil {
            return c.Status(500).JSON(fiber.Map{"error": err.Error()})
        }
        return c.JSON(fiber.Map{"messageId": result.ID})
    })

    app.Listen(":3000")
}`,
  },
  {
    framework: '.NET',
    language: 'csharp',
    installCommand: 'dotnet add package ApexMail',
    description: 'Send email from an ASP.NET Core application.',
    code: `using ApexMail;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(new ApexMailClient(
    Environment.GetEnvironmentVariable("APEXMAIL_API_KEY")!
));

var app = builder.Build();

app.MapPost("/send", async (ApexMailClient client) =>
{
    var result = await client.Messages.SendAsync(new SendMessageRequest
    {
        From = "team@yourapp.com",
        To = "user@example.com",
        Subject = "Welcome!",
        Html = "<p>Welcome!</p>"
    });

    return Results.Ok(new { messageId = result.Id });
});

app.Run();`,
  },
];

// Attach framework examples to all providers
for (const provider of MIGRATION_PROVIDERS) {
  provider.sdkExamples = FRAMEWORK_SDK_EXAMPLES;
}

// ────────────────────────────────────────────────────────────────────
// Page Generator
// ────────────────────────────────────────────────────────────────────

export function generateMigrationPageContent(provider: MigrationProvider): string {
  return JSON.stringify(provider, null, 2);
}

export function getProvider(slug: string): MigrationProvider | undefined {
  return MIGRATION_PROVIDERS.find(p => p.slug === slug);
}

export function getAllProviderSlugs(): string[] {
  return MIGRATION_PROVIDERS.map(p => p.slug);
}
