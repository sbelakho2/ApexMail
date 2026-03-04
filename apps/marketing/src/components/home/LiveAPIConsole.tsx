'use client';

import { useState } from 'react';
import { Copy, Check, Terminal, ExternalLink } from '@/components/ui/icons';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

const curlCommand = `curl -X POST https://api.apexmail.ee/v1/messages \\
  -H "X-API-Key: demo_key_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{
    "from": "demo@apexmail.ee",
    "to": "YOUR_EMAIL",
    "subject": "Your ApexMail Test",
    "html": "<h1>Hello from ApexMail!</h1><p>This email was sent in < 10 seconds, no credit card required.</p>",
    "type": "transactional"
  }'`;

const sdkExamples = {
  typescript: `import { ApexMail } from '@apexmail/sdk';

const client = new ApexMail({
  apiKey: process.env.APEXMAIL_API_KEY!
});

const result = await client.send({
  from: 'hello@yourapp.com',
  to: 'user@example.com',
  subject: 'Welcome aboard!',
  html: '<h1>Welcome!</h1>',
  type: 'transactional',
  metadata: {
    userId: 'usr_123',
    campaign: 'onboarding'
  }
});

console.log(result.id); // "msg_abc123"`,

  python: `from apexmail import ApexMail

client = ApexMail(api_key=os.environ["APEXMAIL_API_KEY"])

result = client.send(
  from_email="hello@yourapp.com",
  to="user@example.com",
  subject="Welcome aboard!",
  html="<h1>Welcome!</h1>",
  type="transactional",
  metadata={
    "user_id": "usr_123",
    "campaign": "onboarding"
  }
)

print(result.id) # "msg_abc123"`,

  go: `package main

import (
  "os"
  "fmt"
  "github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go"
)

func main() {
  client := apexmail.NewClient(os.Getenv("APEXMAIL_API_KEY"))
  
  result, err := client.Send(&apexmail.Message{
    From: "hello@yourapp.com",
    To: "user@example.com",
    Subject: "Welcome aboard!",
    HTML: "<h1>Welcome!</h1>",
    Type: apexmail.Transactional,
    Metadata: map[string]string{
      "userId": "usr_123",
      "campaign": "onboarding",
    },
  })
  
  fmt.Println(result.ID) // "msg_abc123"
}`,

  ruby: `require 'apexmail'

client = ApexMail::Client.new(api_key: ENV['APEXMAIL_API_KEY'])

result = client.send(
  from: 'hello@yourapp.com',
  to: 'user@example.com',
  subject: 'Welcome aboard!',
  html: '<h1>Welcome!</h1>',
  type: :transactional,
  metadata: {
    user_id: 'usr_123',
    campaign: 'onboarding'
  }
)

puts result.id # "msg_abc123"`,
};

const languages = [
  { id: 'typescript', name: 'TypeScript' },
  { id: 'python', name: 'Python' },
  { id: 'go', name: 'Go' },
  { id: 'ruby', name: 'Ruby' },
];

export function LiveAPIConsole() {
  const [email, setEmail] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState('typescript');
  const [copied, setCopied] = useState<'idle' | 'ok' | 'err'>('idle');
  const [emailTouched, setEmailTouched] = useState(false);

  const emailError =
    emailTouched && (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      ? 'Please enter a valid email address'
      : '';

  const handleCopy = async () => {
    const text = curlCommand.replace('YOUR_EMAIL', email || 'your@email.com');
    try {
      await navigator.clipboard.writeText(text);
      setCopied('ok');
    } catch {
      // Clipboard write failed (permissions denied or insecure context)
      setCopied('err');
    } finally {
      setTimeout(() => setCopied('idle'), 2500);
    }
  };

  return (
    <section id="api-console" className="py-20 lg:py-32 relative bg-surface-50">
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="animate-in text-center mb-12">
          <h2 className="section-title mb-4">
            <span className="text-surface-900">The</span>{' '}
            <span className="text-brand-500">Developer API</span>
          </h2>
          <p className="text-surface-600 text-lg max-w-2xl mx-auto leading-relaxed">
            A clean, idiomatic API with official SDKs for every major language. Create a free account to start sending.
          </p>
        </div>

        {/* Live Console */}
        <div className="animate-in delay-200 grid lg:grid-cols-2 gap-8 mb-16">
          {/* Left - cURL Preview + Sign-up CTA */}
          <div className="p-6 sm:p-8 bg-white rounded-lg border border-surface-200 shadow-sm">
            <div className="flex flex-wrap items-center gap-3 mb-8">
              <div className="w-10 h-10 rounded-sm bg-surface-50 flex items-center justify-center border border-surface-200 text-surface-900">
                <Terminal className="w-5 h-5" strokeWidth={1.5} />
              </div>
              <div>
                <h3 className="font-bold text-surface-900 text-[14px]">API Preview</h3>
                <p className="text-[14px] text-surface-500 font-medium">Real sending requires a free account</p>
              </div>
            </div>

            {/* Recipient preview (cosmetic only — not submitted) */}
            <div className="mb-6">
              <label htmlFor="api-console-email" className="block text-[14px] font-semibold text-surface-700 mb-2">
                Recipient address <span className="text-surface-400 font-normal">(preview only)</span>
              </label>
              <input
                id="api-console-email"
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (!emailTouched) setEmailTouched(true);
                }}
                onBlur={() => setEmailTouched(true)}
                placeholder="you@example.com"
                aria-describedby="email-hint"
                className="w-full px-4 py-3 bg-white border border-surface-200 rounded-sm text-surface-900 placeholder-surface-400 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/10 transition-colors"
              />
              <span id="email-hint" className="text-xs text-surface-400 mt-1 block">
                Updates the cURL preview below. No email is sent from this page.
              </span>
              {emailError ? (
                <p className="mt-2 text-xs font-semibold text-red-600" role="alert" aria-live="assertive">
                  {emailError}
                </p>
              ) : null}
            </div>

            {/* Curl Command Preview */}
            <div className="mb-8">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[14px] font-semibold text-surface-700">cURL command</span>
                <Button
                  onClick={handleCopy}
                  aria-label={
                    copied === 'ok'
                      ? 'Copied to clipboard'
                      : copied === 'err'
                      ? 'Copy failed — try manually'
                      : 'Copy cURL command'
                  }
                  variant="outline"
                  size="sm"
                  className={cn('gap-1.5 text-[14px]', copied === 'err' && 'text-red-600 border-red-200')}
                >
                  {copied === 'ok' ? (
                    <><Check className="w-4 h-4" /> Copied</>
                  ) : copied === 'err' ? (
                    <>Failed—copy manually</>
                  ) : (
                    <><Copy className="w-4 h-4" /> Copy</>
                  )}
                </Button>
              </div>
              <div className="bg-surface-900 rounded-lg p-5 text-[13px] font-mono overflow-x-auto border border-surface-800 shadow-inner">
                <pre className="text-surface-300 whitespace-pre leading-relaxed">{curlCommand.replace('YOUR_EMAIL', email || 'your@email.com')}</pre>
              </div>
            </div>

            {/* CTA — real sending requires an account */}
            <Link
              href="https://app.apexmail.ee/signup"
              className="btn-primary w-full flex items-center justify-center gap-2 py-3 text-sm font-semibold"
            >
              <ExternalLink className="w-4 h-4" aria-hidden="true" />
              Create free account &amp; send real emails
            </Link>
            <p className="text-center text-xs text-surface-400 mt-3">
              No credit card required · Free tier included
            </p>
          </div>

          {/* Right - SDK Examples */}
          <div className="p-6 sm:p-8 bg-white rounded-lg border border-surface-200 shadow-sm flex flex-col">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h3 className="font-bold text-surface-900 text-sm">Official SDKs</h3>
                <p className="text-xs text-surface-500 font-medium mt-0.5">npm install @apexmail/sdk</p>
              </div>
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-surface-100" />
                <div className="w-2.5 h-2.5 rounded-full bg-surface-100" />
                <div className="w-2.5 h-2.5 rounded-full bg-surface-100" />
              </div>
            </div>

            {/* Language Tabs */}
            <div className="flex flex-wrap items-center gap-1 mb-6 border-b border-surface-100 pb-0">
              {languages.map((lang) => (
                <button
                  key={lang.id}
                  onClick={() => setSelectedLanguage(lang.id)}
                  aria-label={`Show ${lang.name} example`}
                  className={cn(
                    'px-4 py-4 text-xs font-bold transition-colors relative',
                    selectedLanguage === lang.id
                      ? 'text-surface-900'
                      : 'text-surface-400 hover:text-surface-600'
                  )}
                >
                  {lang.name}
                  {selectedLanguage === lang.id && (
                    <div layoutId="activeTab" className="animate-in absolute bottom-[-5px] left-0 right-0 h-0.5 bg-surface-900" />
                  )}
                </button>
              ))}
            </div>

            {/* Code Example Container */}
            <div className="flex-1 bg-surface-900 rounded-lg border border-surface-800 overflow-hidden flex flex-col min-h-[300px] shadow-inner">
              <div className="px-5 py-3 border-b border-surface-800 bg-surface-950/50 flex items-center justify-between">
                <span className="text-xs font-mono text-surface-500 font-bold">{selectedLanguage}.example</span>
              </div>
              <div className="flex-1 p-0 overflow-auto custom-scrollbar">
                <CodeBlock 
                  code={sdkExamples[selectedLanguage as keyof typeof sdkExamples]} 
                  language={selectedLanguage}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
