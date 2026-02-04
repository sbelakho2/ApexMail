'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { Play, Copy, Check, Terminal, Loader2 } from 'lucide-react';
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

print(result.id) # "msg_abc123"`,

  go: `package main

import (
  "os"
  "fmt"
  "github.com/apexmail/apexmail-go"
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

    // Simulate API call
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
    <section ref={ref} id="api-console" className="py-20 lg:py-32 relative bg-surface-50">
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-12"
        >
          <h2 className="section-title mb-4">
            <span className="text-surface-900">Try It</span>{' '}
            <span className="text-primary-600">Right Now</span>
          </h2>
          <p className="text-surface-600 text-lg max-w-2xl mx-auto leading-relaxed">
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
          <div className="p-8 bg-white rounded-xl border border-surface-200 shadow-sm">
            <div className="flex items-center gap-3 mb-8">
              <div className="w-10 h-10 rounded-lg bg-surface-50 flex items-center justify-center border border-surface-200 text-surface-900">
                <Terminal className="w-5 h-5" strokeWidth={1.5} />
              </div>
              <div>
                <h3 className="font-bold text-surface-900 text-sm">Live API Console</h3>
                <p className="text-xs text-surface-500 font-medium">Test delivery speed in real-time</p>
              </div>
              <span className="ml-auto text-[10px] px-2 py-1 rounded bg-surface-50 text-surface-600 border border-surface-200 font-bold">
                No Login
              </span>
            </div>

            {/* Email Input */}
            <div className="mb-6">
              <label htmlFor="api-console-email" className="block text-xs font-semibold text-surface-700 mb-2">Your email address</label>
              <input
                id="api-console-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                aria-describedby="email-hint"
                className="w-full px-4 py-3 bg-white border border-surface-200 rounded-lg text-surface-900 placeholder-surface-400 focus:outline-none focus:border-primary-500 focus:ring-2 focus:ring-primary-500/10 transition-colors"
              />
              <span id="email-hint" className="sr-only">Enter your email to receive a test email from the API</span>
            </div>

            {/* Curl Command Preview */}
            <div className="mb-8">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-surface-700">cURL command</span>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1.5 text-[10px] font-bold text-surface-600 hover:text-surface-900 transition-colors bg-white px-2 py-1 rounded border border-surface-200 hover:bg-surface-50"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="bg-surface-900 rounded-lg p-5 text-[13px] font-mono overflow-x-auto border border-surface-800 shadow-inner">
                <pre className="text-surface-300 whitespace-pre-wrap leading-relaxed">{curlCommand.replace('YOUR_EMAIL', email || 'your@email.com')}</pre>
              </div>
            </div>

            {/* Send Button */}
            <button
              onClick={handleSend}
              disabled={isSending}
              className={cn(
                'w-full inline-flex items-center justify-center px-6 py-3.5 text-sm font-bold text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors disabled:opacity-70 disabled:cursor-not-allowed shadow-sm',
              )}
            >
              {isSending ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                  Processing Delivery...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current mr-2" />
                  Run Request
                </>
              )}
            </button>

            {/* Result Message */}
            {sendResult && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn(
                  'mt-6 p-4 rounded-lg border text-sm font-semibold flex items-center gap-3',
                  sendResult.success
                    ? 'bg-emerald-50 border-emerald-100 text-emerald-700'
                    : 'bg-red-50 border-red-100 text-red-700'
                )}
              >
                <div className={cn('w-2 h-2 rounded-full shrink-0', sendResult.success ? 'bg-emerald-500' : 'bg-red-500')} />
                {sendResult.message}
              </motion.div>
            )}
          </div>

          {/* Right - SDK Examples */}
          <div className="p-8 bg-white rounded-xl border border-surface-200 shadow-sm flex flex-col">
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
            <div className="flex items-center gap-1 mb-6 border-b border-surface-100 pb-1">
              {languages.map((lang) => (
                <button
                  key={lang.id}
                  onClick={() => setSelectedLanguage(lang.id)}
                  className={cn(
                    'px-4 py-2 text-xs font-bold transition-colors relative',
                    selectedLanguage === lang.id
                      ? 'text-surface-900'
                      : 'text-surface-400 hover:text-surface-600'
                  )}
                >
                  {lang.name}
                  {selectedLanguage === lang.id && (
                    <motion.div
                      layoutId="activeTab"
                      className="absolute bottom-[-5px] left-0 right-0 h-0.5 bg-surface-900"
                    />
                  )}
                </button>
              ))}
            </div>

            {/* Code Example Container */}
            <div className="flex-1 bg-surface-900 rounded-lg border border-surface-800 overflow-hidden flex flex-col min-h-[300px] shadow-inner">
              <div className="px-5 py-3 border-b border-surface-800 bg-surface-950/50 flex items-center justify-between">
                <span className="text-[10px] font-mono text-surface-500 font-bold">{selectedLanguage}.example</span>
              </div>
              <div className="flex-1 p-0 overflow-auto custom-scrollbar">
                <CodeBlock 
                  code={sdkExamples[selectedLanguage as keyof typeof sdkExamples]} 
                  language={selectedLanguage === 'typescript' ? 'typescript' : selectedLanguage === 'go' ? 'go' : 'python'}
                />
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
