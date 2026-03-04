'use client';

import { useState } from 'react';
import { ChevronRight, Send, Users, BarChart3, Webhook, Settings } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

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
        path: '/v1/messages',
        description: 'Send a single email',
        example: `{
  "to": "user@example.com",
  "subject": "Hello!",
  "html": "<h1>Welcome</h1>"
}`,
      },
      {
        method: 'POST',
        path: '/v1/messages/batch',
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
        path: '/v1/messages',
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
  const [selectedCategory, setSelectedCategory] = useState<string>('Sending');
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);

  const category = categories.find((c) => c.name === selectedCategory) || categories[0];

  return (
    <section className="py-20 lg:py-32 relative bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
            <div className="animate-in inline-flex items-center gap-2 px-3 py-1 rounded-full bg-surface-100/50 text-surface-900 border border-surface-200 text-xs font-medium mb-4">
              <Settings className="w-4 h-4 text-surface-500" />
              Endpoint Explorer
            </div>
            <h2 className="animate-in delay-100 text-3xl lg:text-4xl font-semibold text-surface-900 mb-4 tracking-tight">
              Explore the Full API
            </motion.h2>
            <p className="animate-in delay-200 text-lg text-surface-600 max-w-2xl mx-auto leading-relaxed font-medium">
              Browse all available endpoints. Click any endpoint to see request/response examples.
            </p>
          </div>

          <div className="animate-in delay-300 grid lg:grid-cols-4 gap-6">
            {/* Categories */}
            <div className="lg:col-span-1 space-y-2">
              {categories.map((cat) => (
                <button
                  key={cat.name}
                  onClick={() => {
                    setSelectedCategory(cat.name);
                    setSelectedEndpoint(null);
                  }}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all font-medium text-xs',
                    selectedCategory === cat.name
                      ? 'bg-surface-100 text-surface-900'
                      : 'text-surface-500 hover:text-surface-900 hover:bg-surface-50'
                  )}
                >
                  <cat.icon className="w-4 h-4" />
                  <span>{cat.name}</span>
                  <ChevronRight className="w-4 h-4 ml-auto opacity-50" />
                </button>
              ))}
            </div>

            {/* Endpoints List */}
            <div className="lg:col-span-3">
              <div className="bg-white border border-surface-200 shadow-sm rounded-lg overflow-hidden">
                <div className="divide-y divide-surface-100">
                  {category.endpoints.map((endpoint) => (
                    <div
                      key={endpoint.path}
                      onClick={() =>
                        setSelectedEndpoint(selectedEndpoint?.path === endpoint.path ? null : endpoint)
                      }
                      className={cn(
                        'p-6 cursor-pointer transition-colors',
                        selectedEndpoint?.path === endpoint.path
                          ? 'bg-surface-50'
                          : 'hover:bg-surface-50/50'
                      )}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <span
                          className={cn(
                            'px-2.5 py-0.5 text-xs font-medium tracking-tight rounded-md',
                            endpoint.method === 'GET'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-100'
                              : endpoint.method === 'POST'
                              ? 'bg-primary-50 text-primary-700 border border-primary-100'
                              : endpoint.method === 'PUT'
                              ? 'bg-amber-50 text-amber-700 border border-amber-100'
                              : 'bg-red-50 text-red-700 border border-red-100'
                          )}
                        >
                          {endpoint.method}
                        </span>
                        <span className="text-surface-900 font-mono text-sm font-medium">{endpoint.path}</span>
                      </div>
                      <p className="text-sm text-surface-600 font-medium">{endpoint.description}</p>
                      
                      {selectedEndpoint?.path === endpoint.path && (
                        <div className="animate-in mt-6 pt-6 border-t border-surface-200">
                          <div className="text-xs font-semibold text-surface-500 mb-3">Example Request/Response</div>
                          <pre className="text-xs text-surface-300 font-mono bg-surface-900 p-4 rounded-lg overflow-auto shadow-inner border border-surface-800">
                            {endpoint.example}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
      </div>
    </section>
  );
}
