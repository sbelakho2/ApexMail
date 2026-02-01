'use client';

import { motion } from 'framer-motion';
import { useInView } from 'react-intersection-observer';
import { useState } from 'react';
import { ChevronRight, Send, Users, BarChart3, Webhook, Shield, Settings } from 'lucide-react';

interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  description: string;
  example: string;
}

interface EndpointCategory {
  name: string;
  icon: typeof Send;
  endpoints: Endpoint[];
}

const categories: EndpointCategory[] = [
  {
    name: 'Sending',
    icon: Send,
    endpoints: [
      {
        method: 'POST',
        path: '/v1/send',
        description: 'Send a single email',
        example: `{
  "to": "user@example.com",
  "subject": "Hello!",
  "html": "<h1>Welcome</h1>"
}`,
      },
      {
        method: 'POST',
        path: '/v1/batch',
        description: 'Send up to 1000 emails in a single request',
        example: `{
  "messages": [
    { "to": "a@example.com", "subject": "Hi A" },
    { "to": "b@example.com", "subject": "Hi B" }
  ]
}`,
      },
      {
        method: 'POST',
        path: '/v1/send/template',
        description: 'Send using a pre-defined template',
        example: `{
  "template_id": "tmpl_welcome",
  "to": "user@example.com",
  "variables": { "name": "John" }
}`,
      },
    ],
  },
  {
    name: 'Contacts',
    icon: Users,
    endpoints: [
      {
        method: 'POST',
        path: '/v1/contacts',
        description: 'Create a new contact',
        example: `{
  "email": "user@example.com",
  "name": "John Doe",
  "tags": ["newsletter"]
}`,
      },
      {
        method: 'GET',
        path: '/v1/contacts/{id}',
        description: 'Retrieve contact details',
        example: `// Response
{
  "id": "con_abc123",
  "email": "user@example.com",
  "subscribed": true
}`,
      },
      {
        method: 'DELETE',
        path: '/v1/contacts/{id}',
        description: 'Delete a contact (GDPR compliant)',
        example: `// Response
{
  "deleted": true,
  "deletion_certificate": "cert_xyz"
}`,
      },
    ],
  },
  {
    name: 'Analytics',
    icon: BarChart3,
    endpoints: [
      {
        method: 'GET',
        path: '/v1/analytics/summary',
        description: 'Get sending statistics',
        example: `// Response
{
  "sent": 10000,
  "delivered": 9850,
  "opened": 4200,
  "clicked": 1800
}`,
      },
      {
        method: 'GET',
        path: '/v1/messages/{id}/events',
        description: 'Get all events for a message',
        example: `// Response
{
  "events": [
    { "type": "sent", "at": "..." },
    { "type": "delivered", "at": "..." }
  ]
}`,
      },
    ],
  },
  {
    name: 'Webhooks',
    icon: Webhook,
    endpoints: [
      {
        method: 'POST',
        path: '/v1/webhooks',
        description: 'Create a webhook endpoint',
        example: `{
  "url": "https://your.app/webhook",
  "events": ["email.delivered", "email.bounced"]
}`,
      },
      {
        method: 'GET',
        path: '/v1/webhooks',
        description: 'List all webhook endpoints',
        example: `// Response
{
  "webhooks": [
    { "id": "wh_123", "url": "...", "active": true }
  ]
}`,
      },
    ],
  },
];

export function EndpointExplorer() {
  const [ref, inView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [selectedCategory, setSelectedCategory] = useState<string>('Sending');
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);

  const category = categories.find((c) => c.name === selectedCategory) || categories[0];

  return (
    <section ref={ref} className="py-20 lg:py-32 relative bg-surface-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-400 text-sm mb-4"
          >
            <Settings className="w-4 h-4" />
            Endpoint Explorer
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.1 }}
            className="text-3xl lg:text-4xl font-bold text-white mb-4"
          >
            Explore the Full API
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.2 }}
            className="text-lg text-surface-400 max-w-2xl mx-auto"
          >
            Browse all available endpoints. Click any endpoint to see request/response examples.
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
          className="grid lg:grid-cols-4 gap-6"
        >
          {/* Categories */}
          <div className="lg:col-span-1 space-y-2">
            {categories.map((cat) => (
              <button
                key={cat.name}
                onClick={() => {
                  setSelectedCategory(cat.name);
                  setSelectedEndpoint(null);
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                  selectedCategory === cat.name
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                    : 'text-surface-400 hover:text-white hover:bg-surface-800'
                }`}
              >
                <cat.icon className="w-5 h-5" />
                <span className="font-medium">{cat.name}</span>
                <ChevronRight className="w-4 h-4 ml-auto" />
              </button>
            ))}
          </div>

          {/* Endpoints List */}
          <div className="lg:col-span-3">
            <div className="glass-card overflow-hidden">
              <div className="divide-y divide-surface-700">
                {category.endpoints.map((endpoint) => (
                  <div
                    key={endpoint.path}
                    onClick={() =>
                      setSelectedEndpoint(selectedEndpoint?.path === endpoint.path ? null : endpoint)
                    }
                    className={`p-4 cursor-pointer transition-colors ${
                      selectedEndpoint?.path === endpoint.path
                        ? 'bg-cyan-500/10'
                        : 'hover:bg-surface-800/50'
                    }`}
                  >
                    <div className="flex items-center gap-3 mb-2">
                      <span
                        className={`px-2 py-0.5 text-xs font-mono rounded ${
                          endpoint.method === 'GET'
                            ? 'bg-green-500/20 text-green-400'
                            : endpoint.method === 'POST'
                            ? 'bg-blue-500/20 text-blue-400'
                            : endpoint.method === 'PUT'
                            ? 'bg-yellow-500/20 text-yellow-400'
                            : 'bg-red-500/20 text-red-400'
                        }`}
                      >
                        {endpoint.method}
                      </span>
                      <span className="text-white font-mono text-sm">{endpoint.path}</span>
                    </div>
                    <p className="text-sm text-surface-400">{endpoint.description}</p>

                    {selectedEndpoint?.path === endpoint.path && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-4 pt-4 border-t border-surface-700"
                      >
                        <div className="text-xs text-surface-500 mb-2">Example</div>
                        <pre className="text-sm text-surface-300 font-mono bg-surface-900 p-4 rounded-lg overflow-auto">
                          {endpoint.example}
                        </pre>
                      </motion.div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
