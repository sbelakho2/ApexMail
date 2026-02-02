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
 <section ref={ref} id="api-console" className="py-20 lg:py-32 relative bg-white">
 <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
 {/* Section Header */}
 <motion.div
 initial={{ opacity: 0, y: 20 }}
 animate={inView ? { opacity: 1, y: 0 } : {}}
 className="text-center mb-12"
 >
 <h2 className="section-title mb-4">
 <span className="text-surface-900">Try It</span>{' '}
 <span className="text-primary-500">Right Now</span>
 </h2>
 <p className="text-surface-600 text-[17px] max-w-2xl mx-auto leading-relaxed">
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
        <div className="premium-card p-8 bg-surface-50 border-surface-200/60 shadow-xl">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center border border-primary-100">
              <Terminal className="w-5 h-5 text-primary-600" />
            </div>
            <div>
              <h3 className="font-bold text-surface-900">Live API Console</h3>
              <p className="text-[12px] text-surface-500 font-medium">Test our delivery speed in real-time</p>
            </div>
            <span className="ml-auto text-[10px] px-2.5 py-1 rounded-md bg-white text-primary-600 border border-primary-200 font-bold uppercase tracking-widest shadow-sm">
              No Login
            </span>
          </div>

          {/* Email Input */}
          <div className="mb-6">
            <label className="block text-[11px] font-bold text-surface-400 uppercase tracking-widest mb-2.5">Your email address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="w-full px-4 py-3 bg-white border border-surface-200 rounded-md text-surface-900 placeholder-surface-400 focus:outline-none focus:border-primary-500 focus:ring-4 focus:ring-primary-500/10 transition-all shadow-sm"
            />
          </div>

          {/* Curl Command Preview */}
          <div className="mb-8">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-bold text-surface-400 uppercase tracking-widest">cURL command</span>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 text-xs font-bold text-primary-600 hover:text-primary-700 transition-colors bg-white px-2 py-1 rounded-md border border-surface-200 shadow-sm"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div className="bg-surface-900 rounded-xl p-5 text-[13px] font-mono overflow-x-auto shadow-inner border border-surface-800 relative group">
              <pre className="text-surface-300 whitespace-pre-wrap leading-relaxed">{curlCommand.replace('YOUR_EMAIL', email || 'your@email.com')}</pre>
            </div>
          </div>

          {/* Send Button */}
          <button
            onClick={handleSend}
            disabled={isSending}
            className={cn(
              'w-full btn-primary py-4 rounded-xl flex items-center justify-center gap-3 font-bold text-[15px] shadow-lg shadow-primary-500/20 active:scale-[0.98] transition-all',
              isSending && 'opacity-70 cursor-not-allowed shadow-none'
            )}
          >
            {isSending ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Processing Delivery...
              </>
            ) : (
              <>
                <Play className="w-5 h-5 fill-current" />
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
                'mt-6 p-4 rounded-xl border text-sm font-semibold flex items-center gap-3 shadow-sm',
                sendResult.success
                  ? 'bg-success-50 border-success-100 text-success-700'
                  : 'bg-danger-50 border-danger-100 text-danger-700'
              )}
            >
              <div className={cn('w-2 h-2 rounded-full shrink-0', sendResult.success ? 'bg-success-500' : 'bg-danger-500')} />
              {sendResult.message}
            </motion.div>
          )}
        </div>

        {/* Right - SDK Examples */}
        <div className="premium-card p-8 bg-white border-surface-200/60 shadow-xl flex flex-col">
          <div className="flex items-center justify-between mb-8">
            <div>
              <h3 className="font-bold text-surface-900">Official SDKs</h3>
              <p className="text-[12px] text-surface-500 font-medium tracking-tight">npm install @apexmail/sdk</p>
            </div>
            <div className="flex gap-1">
              <div className="w-2 h-2 rounded-full bg-surface-200" />
              <div className="w-2 h-2 rounded-full bg-surface-200" />
              <div className="w-2 h-2 rounded-full bg-surface-200" />
            </div>
          </div>

          {/* Language Tabs */}
          <div className="flex items-center gap-1 mb-6 p-1 bg-surface-50 rounded-xl border border-surface-100 shadow-inner">
            {languages.map((lang) => (
              <button
                key={lang.id}
                onClick={() => setSelectedLanguage(lang.id)}
                className={cn(
                  'flex-1 py-2.5 px-4 rounded-lg text-[11px] font-bold uppercase tracking-widest transition-all duration-200',
                  selectedLanguage === lang.id
                    ? 'bg-white text-primary-600 shadow-sm border border-surface-200/50'
                    : 'text-surface-400 hover:text-surface-600'
                )}
              >
                {lang.name}
              </button>
            ))}
          </div>

          {/* Code Example Container */}
          <div className="flex-1 bg-surface-900 rounded-xl border border-surface-800 shadow-2xl overflow-hidden flex flex-col min-h-[300px]">
            <div className="px-5 py-3 border-b border-surface-800 bg-surface-900/50 flex items-center justify-between">
              <span className="text-[11px] font-mono text-surface-500 uppercase tracking-widest">{selectedLanguage}.example</span>
              <div className="w-2 h-2 rounded-full bg-primary-500 animate-pulse" />
            </div>
            <div className="flex-1 p-0 overflow-auto custom-scrollbar">
              <CodeBlock 
                code={sdkExamples[selectedLanguage as keyof typeof sdkExamples]} 
                language={selectedLanguage === 'typescript' ? 'typescript' : selectedLanguage === 'go' ? 'go' : 'python'}
              />
            </div>
          </div>

 {/* Documentation Link */}
 <a
 href="https://docs.apexmail.ee"
 target="_blank"
 rel="noopener noreferrer"
 className="mt-4 flex items-center justify-center gap-2 text-sm font-bold text-primary-600 hover:text-primary-700 transition-colors"
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
 <div key={item.label} className="text-center p-6 rounded-lg bg-surface-50 border border-surface-100">
 <div className="text-2xl font-bold text-primary-600 mb-1 tabular-nums">{item.value}</div>
 <div className="text-[10px] font-bold text-surface-500 uppercase tracking-widest">{item.label}</div>
 </div>
 ))}
 </motion.div>
 </div>
 </section>
 );
}
