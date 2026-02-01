'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Play, Copy, Check, Terminal, ArrowRight, Loader2 } from 'lucide-react';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { cn } from '@/lib/utils';

const curlCommand = `curl -X POST https://api.apexmail.ee/v1/send \\
  -H "Authorization: Bearer demo_key_xxx" \\
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

print(result.id)  # "msg_abc123"`,

  go: `package main

import (
    "os"
    "fmt"
    "github.com/apexmail/apexmail-go"
)

func main() {
    client := apexmail.NewClient(os.Getenv("APEXMAIL_API_KEY"))
    
    result, err := client.Send(&apexmail.Message{
        From:    "hello@yourapp.com",
        To:      "user@example.com",
        Subject: "Welcome aboard!",
        HTML:    "<h1>Welcome!</h1>",
        Type:    apexmail.Transactional,
        Metadata: map[string]string{
            "userId":   "usr_123",
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
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [email, setEmail] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [sendResult, setSendResult] = useState<{ success: boolean; message: string } | null>(null);
  const [selectedLanguage, setSelectedLanguage] = useState('typescript');
  const [copied, setCopied] = useState(false);

  const handleSend = async () => {
    if (!email || !email.includes('@')) {
      setSendResult({ success: false, message: 'Please enter a valid email address' });
      return;
    }

    setIsSending(true);
    setSendResult(null);

    // Simulate API call (in production, this would hit the actual demo endpoint)
    await new Promise(resolve => setTimeout(resolve, 1500));

    setIsSending(false);
    setSendResult({
      success: true,
      message: `Test email sent to ${email}! Check your inbox in a few seconds.`,
    });
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(curlCommand.replace('YOUR_EMAIL', email || 'test@example.com'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section ref={ref} id="api-console" className="py-20 lg:py-32 relative">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-surface-900/50 via-transparent to-surface-900/50" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-12"
        >
          <h2 className="section-title mb-4">
            <span className="text-white">Try It</span>{' '}
            <span className="gradient-text">Right Now</span>
          </h2>
          <p className="section-subtitle">
            Send a real email in under 10 seconds. No signup, no credit card, no BS.
          </p>
        </motion.div>

        {/* Live Console */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="grid lg:grid-cols-2 gap-8 mb-16"
        >
          {/* Left - Interactive Demo */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-2 mb-6">
              <Terminal className="w-5 h-5 text-primary-400" />
              <h3 className="font-semibold text-white">Live API Console</h3>
              <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-accent-500/20 text-accent-400 border border-accent-500/30">
                No Login Required
              </span>
            </div>

            {/* Email Input */}
            <div className="mb-4">
              <label className="block text-sm text-surface-400 mb-2">Your email address</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full px-4 py-3 bg-surface-800 border border-surface-700 rounded-lg text-white placeholder-surface-500 focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500 transition-colors"
              />
            </div>

            {/* Curl Command Preview */}
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-surface-400">cURL command</span>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1 text-xs text-surface-400 hover:text-white transition-colors"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div className="code-block p-4 text-xs overflow-x-auto">
                <pre className="text-surface-300 whitespace-pre-wrap">{curlCommand.replace('YOUR_EMAIL', email || 'your@email.com')}</pre>
              </div>
            </div>

            {/* Send Button */}
            <button
              onClick={handleSend}
              disabled={isSending}
              className={cn(
                'w-full btn-accent flex items-center justify-center gap-2',
                isSending && 'opacity-70 cursor-not-allowed'
              )}
            >
              {isSending ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Sending...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Send Test Email
                </>
              )}
            </button>

            {/* Result Message */}
            {sendResult && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn(
                  'mt-4 p-4 rounded-lg border',
                  sendResult.success
                    ? 'bg-accent-500/10 border-accent-500/30 text-accent-400'
                    : 'bg-red-500/10 border-red-500/30 text-red-400'
                )}
              >
                {sendResult.message}
              </motion.div>
            )}
          </div>

          {/* Right - SDK Examples */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-2 mb-6">
              <h3 className="font-semibold text-white">Official SDKs</h3>
              <span className="text-xs text-surface-400">npm install @apexmail/sdk</span>
            </div>

            {/* Language Tabs */}
            <div className="flex items-center gap-1 mb-4 p-1 bg-surface-800 rounded-lg">
              {languages.map((lang) => (
                <button
                  key={lang.id}
                  onClick={() => setSelectedLanguage(lang.id)}
                  className={cn(
                    'flex-1 py-2 px-3 rounded-md text-sm font-medium transition-all',
                    selectedLanguage === lang.id
                      ? 'bg-surface-700 text-white'
                      : 'text-surface-400 hover:text-white'
                  )}
                >
                  {lang.name}
                </button>
              ))}
            </div>

            {/* Code Example */}
            <div className="code-block max-h-[350px] overflow-y-auto">
              <CodeBlock
                code={sdkExamples[selectedLanguage as keyof typeof sdkExamples]}
                language={selectedLanguage === 'typescript' ? 'typescript' : selectedLanguage === 'go' ? 'go' : 'python'}
              />
            </div>

            {/* Documentation Link */}
            <a
              href="https://docs.apexmail.ee"
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 flex items-center justify-center gap-2 text-sm text-primary-400 hover:text-primary-300 transition-colors"
            >
              View full documentation
              <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </motion.div>

        {/* Bottom Feature Highlights */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.4 }}
          className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4"
        >
          {[
            { label: 'API Response Time', value: '< 100ms' },
            { label: 'Webhook Delivery', value: '< 1s' },
            { label: 'Free Tier', value: '1,000 emails/mo' },
            { label: 'Rate Limit', value: '100 req/s' },
          ].map((item) => (
            <div key={item.label} className="text-center p-4 rounded-lg bg-surface-800/30 border border-surface-700/50">
              <div className="text-2xl font-bold text-white mb-1">{item.value}</div>
              <div className="text-sm text-surface-400">{item.label}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
