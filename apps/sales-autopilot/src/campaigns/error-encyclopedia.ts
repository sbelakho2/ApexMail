/**
 * Error Encyclopedia — Auto-generated error documentation pages
 *
 * Every ApexMail error code gets a page with:
 *   • Root cause explanation
 *   • Fix instructions (step-by-step)
 *   • Prevention tips
 *   • Related errors
 *
 * Captures high-intent search traffic from developers debugging issues.
 * Pages are generated at build time from this data.
 */

// Error definitions are data-only — no runtime logger needed.

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface ErrorEntry {
  code: string;
  httpStatus: number;
  title: string;
  category: ErrorCategory;
  description: string;
  commonCauses: string[];
  fix: FixStep[];
  prevention: string[];
  codeExample: CodeExample | null;
  relatedErrors: string[];
  searchKeywords: string[];
}

export interface FixStep {
  step: number;
  title: string;
  description: string;
  code: string | null;
}

export interface CodeExample {
  language: string;
  title: string;
  wrong: string;
  correct: string;
  explanation: string;
}

export type ErrorCategory =
  | 'authentication'
  | 'authorization'
  | 'validation'
  | 'domain'
  | 'delivery'
  | 'rate_limiting'
  | 'webhook'
  | 'template'
  | 'billing'
  | 'server';

// ────────────────────────────────────────────────────────────────────
// Error Definitions
// ────────────────────────────────────────────────────────────────────

export const ERROR_ENTRIES: ErrorEntry[] = [
  // ── Authentication ──
  {
    code: 'AUTH_001',
    httpStatus: 401,
    title: 'Invalid API Key',
    category: 'authentication',
    description: 'The API key provided in the Authorization header is not valid or has been revoked.',
    commonCauses: [
      'Using a test key in production or vice versa',
      'The API key was recently rotated and the old key is still in use',
      'Missing or malformed Authorization header',
      'Extra whitespace in the API key environment variable',
    ],
    fix: [
      { step: 1, title: 'Check your API key', description: 'Go to Dashboard → API Keys and copy your active key.', code: null },
      { step: 2, title: 'Verify the header format', description: 'Ensure you\'re using: Authorization: Bearer <your-key>', code: 'curl -H "Authorization: Bearer am_live_..." https://api.apexmail.ee/v1/messages' },
      { step: 3, title: 'Check for whitespace', description: 'Trim your environment variable. Leading/trailing spaces cause auth failures.', code: 'echo "\'$APEXMAIL_API_KEY\'"  # Check for spaces' },
    ],
    prevention: [
      'Store API keys in environment variables, not in code',
      'Use separate keys for test and production environments',
      'Set up key rotation reminders every 90 days',
    ],
    codeExample: {
      language: 'typescript',
      title: 'Correct API key usage',
      wrong: `// ❌ Hard-coded key
const apexmail = new ApexMail('am_live_abc123');`,
      correct: `// ✅ Environment variable
const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY!);`,
      explanation: 'Always use environment variables for API keys. Never commit keys to source control.',
    },
    relatedErrors: ['AUTH_002', 'AUTH_003'],
    searchKeywords: ['apexmail invalid api key', 'apexmail 401', 'apexmail authentication error'],
  },
  {
    code: 'AUTH_002',
    httpStatus: 401,
    title: 'Expired API Key',
    category: 'authentication',
    description: 'The API key has expired. Keys expire after the rotation period set in your account settings.',
    commonCauses: [
      'Key rotation policy expired the key automatically',
      'Admin manually revoked the key',
    ],
    fix: [
      { step: 1, title: 'Generate a new key', description: 'Go to Dashboard → API Keys → Create Key.', code: null },
      { step: 2, title: 'Update your environment', description: 'Deploy the new key to all services using it.', code: null },
    ],
    prevention: [
      'Set up alerts for upcoming key expirations',
      'Use the API to programmatically rotate keys before expiry',
    ],
    codeExample: null,
    relatedErrors: ['AUTH_001'],
    searchKeywords: ['apexmail expired key', 'apexmail key rotation'],
  },
  {
    code: 'AUTH_003',
    httpStatus: 403,
    title: 'Insufficient Permissions',
    category: 'authorization',
    description: 'The API key does not have permission to perform this action. Check the key\'s scope.',
    commonCauses: [
      'Using a send-only key to manage domains',
      'Key scoped to a different domain or project',
    ],
    fix: [
      { step: 1, title: 'Check key permissions', description: 'Go to Dashboard → API Keys and verify the scopes.', code: null },
      { step: 2, title: 'Create a key with correct scope', description: 'Create a new key with the required permissions for your use case.', code: null },
    ],
    prevention: [
      'Use the principle of least privilege — only grant needed scopes',
      'Document which keys are used for which services',
    ],
    codeExample: null,
    relatedErrors: ['AUTH_001'],
    searchKeywords: ['apexmail 403', 'apexmail insufficient permissions', 'apexmail forbidden'],
  },

  // ── Validation ──
  {
    code: 'VAL_001',
    httpStatus: 422,
    title: 'Invalid Email Address',
    category: 'validation',
    description: 'The recipient email address failed syntax validation.',
    commonCauses: [
      'Typo in the email address',
      'Missing @ symbol or domain part',
      'Using a display name without angle brackets: "Name email@test.com" instead of "Name <email@test.com>"',
    ],
    fix: [
      { step: 1, title: 'Validate before sending', description: 'Use a regex or the SDK\'s built-in validation.', code: null },
      { step: 2, title: 'Check the format', description: 'Email must be in "user@domain.tld" or "Name <user@domain.tld>" format.', code: 'const valid = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);' },
    ],
    prevention: [
      'Validate email addresses at the point of collection (signup forms)',
      'Use double opt-in to confirm email addresses',
    ],
    codeExample: {
      language: 'typescript',
      title: 'Email format validation',
      wrong: `// ❌ No validation
await apexmail.messages.send({ to: userInput });`,
      correct: `// ✅ Validate first
if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(userInput)) {
  throw new Error('Invalid email address');
}
await apexmail.messages.send({ to: userInput });`,
      explanation: 'Always validate email format before making API calls.',
    },
    relatedErrors: ['VAL_002', 'VAL_003'],
    searchKeywords: ['apexmail invalid email', 'apexmail 422', 'apexmail validation error'],
  },
  {
    code: 'VAL_002',
    httpStatus: 422,
    title: 'Missing Required Field',
    category: 'validation',
    description: 'A required field is missing from the request body.',
    commonCauses: [
      'Missing "to", "from", or "subject" field',
      'Empty string passed for a required field',
      'Field name typo (e.g., "too" instead of "to")',
    ],
    fix: [
      { step: 1, title: 'Check required fields', description: 'Every send request needs: to, from, subject, and either html or text.', code: null },
      { step: 2, title: 'Verify field names', description: 'Use the SDK to get type-safe field names.', code: null },
    ],
    prevention: [
      'Use TypeScript SDK for compile-time field validation',
      'Write unit tests for your email-sending functions',
    ],
    codeExample: {
      language: 'typescript',
      title: 'Required fields for sending',
      wrong: `// ❌ Missing 'from' field
await apexmail.messages.send({
  to: 'user@example.com',
  subject: 'Hello',
  html: '<p>Hi</p>',
});`,
      correct: `// ✅ All required fields present
await apexmail.messages.send({
  from: 'team@yourapp.com',   // Required
  to: 'user@example.com',      // Required
  subject: 'Hello',            // Required
  html: '<p>Hi</p>',           // html or text required
});`,
      explanation: 'Include all four required fields in every send request.',
    },
    relatedErrors: ['VAL_001'],
    searchKeywords: ['apexmail missing field', 'apexmail required field', 'apexmail 422'],
  },
  {
    code: 'VAL_003',
    httpStatus: 422,
    title: 'Content Too Large',
    category: 'validation',
    description: 'The email content (including attachments) exceeds the maximum allowed size.',
    commonCauses: [
      'Large attachments (max 25MB total)',
      'Embedded base64 images inflating HTML body size',
    ],
    fix: [
      { step: 1, title: 'Reduce attachment size', description: 'Compress files or use hosted links instead of attachments.', code: null },
      { step: 2, title: 'Host images externally', description: 'Use a CDN for images instead of embedding them in the HTML body.', code: null },
    ],
    prevention: [
      'Use hosted image URLs instead of base64-encoded images',
      'Set file size limits in your upload forms',
    ],
    codeExample: null,
    relatedErrors: ['VAL_002'],
    searchKeywords: ['apexmail content too large', 'apexmail attachment size', 'apexmail max size'],
  },

  // ── Domain ──
  {
    code: 'DOM_001',
    httpStatus: 403,
    title: 'Domain Not Verified',
    category: 'domain',
    description: 'The sender domain has not been verified. You cannot send from an unverified domain.',
    commonCauses: [
      'DNS records not yet added',
      'DNS propagation still in progress (up to 48 hours)',
      'Incorrect DNS record values',
    ],
    fix: [
      { step: 1, title: 'Check domain status', description: 'Go to Dashboard → Domains and check the verification status.', code: 'apexmail domains verify yourapp.com' },
      { step: 2, title: 'Verify DNS records', description: 'Ensure all required TXT, CNAME, and MX records are correctly added.', code: 'dig TXT am._domainkey.yourapp.com' },
      { step: 3, title: 'Wait for propagation', description: 'DNS changes can take up to 48 hours. Check back later.', code: null },
    ],
    prevention: [
      'Verify domains before deploying to production',
      'Set up monitoring for DNS record changes',
      'Use the sandbox mode for testing before domain verification',
    ],
    codeExample: null,
    relatedErrors: ['DOM_002', 'DOM_003'],
    searchKeywords: ['apexmail domain not verified', 'apexmail domain setup', 'apexmail dns'],
  },
  {
    code: 'DOM_002',
    httpStatus: 400,
    title: 'SPF Record Missing',
    category: 'domain',
    description: 'The sender domain does not have the required SPF record for ApexMail.',
    commonCauses: [
      'SPF TXT record not added to DNS',
      'Existing SPF record doesn\'t include ApexMail',
      'Multiple SPF records (only one is allowed per domain)',
    ],
    fix: [
      { step: 1, title: 'Add SPF record', description: 'Add or update your domain\'s TXT record.', code: 'v=spf1 include:spf.apexmail.ee ~all' },
      { step: 2, title: 'Merge existing SPF records', description: 'If you already have an SPF record, add our include.', code: 'v=spf1 include:_spf.google.com include:spf.apexmail.ee ~all' },
    ],
    prevention: [
      'Never create multiple SPF TXT records — merge includes into one',
      'Test with: dig TXT yourapp.com | grep spf',
    ],
    codeExample: null,
    relatedErrors: ['DOM_001', 'DOM_003'],
    searchKeywords: ['apexmail spf', 'apexmail dns spf record', 'email spf setup'],
  },
  {
    code: 'DOM_003',
    httpStatus: 400,
    title: 'DKIM Record Missing',
    category: 'domain',
    description: 'The DKIM CNAME record required for email signing is not found.',
    commonCauses: [
      'CNAME record not added to DNS',
      'Wrong selector name used',
      'DNS cache serving stale data',
    ],
    fix: [
      { step: 1, title: 'Add DKIM CNAME', description: 'Add the CNAME record shown in your domain settings.', code: 'am._domainkey.yourapp.com → dkim.apexmail.ee' },
      { step: 2, title: 'Verify with dig', description: 'Confirm the record resolves correctly.', code: 'dig CNAME am._domainkey.yourapp.com' },
    ],
    prevention: [
      'Add all DNS records at once when setting up a new domain',
      'Use a DNS monitoring tool to detect record changes',
    ],
    codeExample: null,
    relatedErrors: ['DOM_001', 'DOM_002'],
    searchKeywords: ['apexmail dkim', 'apexmail dkim record', 'email dkim setup'],
  },

  // ── Delivery ──
  {
    code: 'DEL_001',
    httpStatus: 200,
    title: 'Hard Bounce',
    category: 'delivery',
    description: 'The recipient\'s mail server permanently rejected the email. The address likely doesn\'t exist.',
    commonCauses: [
      'Recipient email address doesn\'t exist',
      'Domain has no mail server (no MX records)',
      'Mailbox has been deactivated',
    ],
    fix: [
      { step: 1, title: 'Remove the address', description: 'Hard bounces mean the address is permanently invalid. Remove it from your list.', code: null },
      { step: 2, title: 'Check for typos', description: 'Common typos: gmail.con, yahooo.com, outook.com', code: null },
    ],
    prevention: [
      'Use email verification before adding contacts to your list',
      'Implement double opt-in for signups',
      'Regularly clean your mailing lists',
    ],
    codeExample: null,
    relatedErrors: ['DEL_002', 'DEL_003'],
    searchKeywords: ['apexmail hard bounce', 'email bounce', 'email not delivered'],
  },
  {
    code: 'DEL_002',
    httpStatus: 200,
    title: 'Soft Bounce',
    category: 'delivery',
    description: 'The email was temporarily rejected. ApexMail will automatically retry delivery.',
    commonCauses: [
      'Recipient mailbox is full',
      'Recipient server is temporarily unavailable',
      'Message was too large for the recipient\'s server',
    ],
    fix: [
      { step: 1, title: 'Wait for auto-retry', description: 'ApexMail automatically retries soft bounces for up to 72 hours.', code: null },
      { step: 2, title: 'Check if persistent', description: 'If the same address soft-bounces repeatedly, treat it as a hard bounce.', code: null },
    ],
    prevention: [
      'Keep your email content size reasonable',
      'Monitor soft bounce rates — persistent soft bounces indicate list quality issues',
    ],
    codeExample: null,
    relatedErrors: ['DEL_001'],
    searchKeywords: ['apexmail soft bounce', 'email temporary failure', 'email retry'],
  },
  {
    code: 'DEL_003',
    httpStatus: 200,
    title: 'Spam Complaint',
    category: 'delivery',
    description: 'The recipient marked your email as spam. This affects your sender reputation.',
    commonCauses: [
      'Recipient doesn\'t recognize the sender',
      'Email content looks like spam',
      'No easy unsubscribe option',
    ],
    fix: [
      { step: 1, title: 'Add to suppression list', description: 'Never email this recipient again.', code: null },
      { step: 2, title: 'Review your content', description: 'Ensure emails clearly identify your brand and include unsubscribe links.', code: null },
    ],
    prevention: [
      'Always include a clear, visible unsubscribe link',
      'Use recognizable sender name and address',
      'Only email people who have opted in',
      'Keep complaint rate under 0.1%',
    ],
    codeExample: null,
    relatedErrors: ['DEL_001'],
    searchKeywords: ['apexmail spam complaint', 'email marked as spam', 'sender reputation'],
  },

  // ── Rate Limiting ──
  {
    code: 'RATE_001',
    httpStatus: 429,
    title: 'Rate Limit Exceeded',
    category: 'rate_limiting',
    description: 'You\'ve exceeded the API rate limit for your plan. Requests are throttled.',
    commonCauses: [
      'Sending too many API requests per second',
      'Not implementing exponential backoff on retries',
      'Burst sending without using batch API',
    ],
    fix: [
      { step: 1, title: 'Implement backoff', description: 'Wait and retry with exponential backoff.', code: null },
      { step: 2, title: 'Use batch sending', description: 'Send up to 100 emails in a single API call using the batch endpoint.', code: null },
      { step: 3, title: 'Check rate limit headers', description: 'Use X-RateLimit-Remaining and X-RateLimit-Reset headers to pace requests.', code: null },
    ],
    prevention: [
      'Implement client-side rate limiting',
      'Use the batch API for bulk sends',
      'Spread sends over time rather than bursting',
    ],
    codeExample: {
      language: 'typescript',
      title: 'Handling rate limits',
      wrong: `// ❌ No rate limit handling
for (const email of emails) {
  await apexmail.messages.send({ to: email, ... });
}`,
      correct: `// ✅ Batch sending with rate limit handling
const batches = chunk(emails, 100);
for (const batch of batches) {
  try {
    await apexmail.messages.sendBatch(batch.map(email => ({
      to: email,
      from: 'team@yourapp.com',
      subject: 'Update',
      html: content,
    })));
  } catch (e) {
    if (e.status === 429) {
      const retryAfter = e.headers['retry-after'];
      await sleep(retryAfter * 1000);
    }
  }
}`,
      explanation: 'Use batch sending and handle 429 responses with proper backoff.',
    },
    relatedErrors: [],
    searchKeywords: ['apexmail rate limit', 'apexmail 429', 'apexmail too many requests'],
  },

  // ── Webhook ──
  {
    code: 'HOOK_001',
    httpStatus: 400,
    title: 'Webhook Signature Verification Failed',
    category: 'webhook',
    description: 'The webhook signature does not match the expected value. The request may be forged.',
    commonCauses: [
      'Using the wrong webhook signing secret',
      'Request body was modified by a proxy or middleware',
      'Using the parsed JSON body instead of the raw body for verification',
    ],
    fix: [
      { step: 1, title: 'Use raw body', description: 'Verify the signature against the raw request body, not the parsed JSON.', code: null },
      { step: 2, title: 'Check signing secret', description: 'Ensure you\'re using the correct webhook signing secret from your dashboard.', code: null },
    ],
    prevention: [
      'Always verify webhook signatures in production',
      'Use the SDK\'s built-in verification method',
      'Ensure no middleware modifies the request body before verification',
    ],
    codeExample: {
      language: 'typescript',
      title: 'Webhook signature verification',
      wrong: `// ❌ Using parsed body
app.post('/webhook', express.json(), (req, res) => {
  verify(JSON.stringify(req.body), signature); // Wrong!
});`,
      correct: `// ✅ Using raw body
app.post('/webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const valid = verifyWebhook({
      payload: req.body,         // Raw Buffer
      signature: req.headers['x-apexmail-signature'],
      secret: process.env.APEXMAIL_WEBHOOK_SECRET,
    });
  }
);`,
      explanation: 'Always use the raw request body for signature verification. JSON.stringify may reorder fields.',
    },
    relatedErrors: [],
    searchKeywords: ['apexmail webhook signature', 'apexmail webhook verification', 'webhook invalid signature'],
  },

  // ── Template ──
  {
    code: 'TPL_001',
    httpStatus: 422,
    title: 'Template Variable Not Found',
    category: 'template',
    description: 'A template references a variable that was not provided in the send request.',
    commonCauses: [
      'Variable name mismatch between template and API call',
      'Typo in variable name (case-sensitive)',
      'Nested variable path not structured correctly',
    ],
    fix: [
      { step: 1, title: 'Check variable names', description: 'Ensure the variables in your send request match the template exactly.', code: null },
      { step: 2, title: 'Provide all variables', description: 'Pass all required template variables in the "variables" field.', code: null },
    ],
    prevention: [
      'Use TypeScript template types for compile-time variable checking',
      'Test templates with all required variables before deploying',
    ],
    codeExample: {
      language: 'typescript',
      title: 'Providing template variables',
      wrong: `// ❌ Missing 'userName' variable
await apexmail.messages.send({
  to: 'user@example.com',
  from: 'team@yourapp.com',
  templateId: 'tmpl_welcome',
  variables: { company: 'Acme' }, // Missing userName!
});`,
      correct: `// ✅ All template variables provided
await apexmail.messages.send({
  to: 'user@example.com',
  from: 'team@yourapp.com',
  templateId: 'tmpl_welcome',
  variables: {
    userName: 'Alice',
    company: 'Acme',
  },
});`,
      explanation: 'Provide all variables referenced in the template with {{variableName}} syntax.',
    },
    relatedErrors: ['VAL_002'],
    searchKeywords: ['apexmail template variable', 'apexmail template error', 'template missing variable'],
  },
];

// ────────────────────────────────────────────────────────────────────
// Lookup Helpers
// ────────────────────────────────────────────────────────────────────

export function getErrorEntry(code: string): ErrorEntry | undefined {
  return ERROR_ENTRIES.find(e => e.code === code);
}

export function getErrorsByCategory(category: ErrorCategory): ErrorEntry[] {
  return ERROR_ENTRIES.filter(e => e.category === category);
}

export function getAllErrorCodes(): string[] {
  return ERROR_ENTRIES.map(e => e.code);
}

export function searchErrors(query: string): ErrorEntry[] {
  const q = query.toLowerCase();
  return ERROR_ENTRIES.filter(e =>
    e.code.toLowerCase().includes(q) ||
    e.title.toLowerCase().includes(q) ||
    e.description.toLowerCase().includes(q) ||
    e.searchKeywords.some(k => k.includes(q))
  );
}
