const http = require('http');
const { URL } = require('url');

const port = Number(process.env.MOCK_API_PORT || 3001);

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function route(pathname) {
  if (pathname === '/health') return { ok: true };
  if (pathname === '/v1/auth/me') return { id: 'user_test', email: 'test@apexmail.local' };
  if (pathname === '/v1/dashboard/stats') {
    return {
      sent: 120000,
      delivered: 117900,
      opens: 54321,
      clicks: 9876,
      bounceRate: 0.8,
      complaintRate: 0.02,
    };
  }
  if (pathname === '/v1/analytics/dashboard') {
    return {
      dashboard: {
        period: { since: '2025-01-01T00:00:00.000Z', until: '2025-02-01T00:00:00.000Z' },
        messages: { total: 120000, queued: 1200, sent: 118800, delivered: 117900, failed: 900 },
        engagement: {
          sent: 118800,
          delivered: 117900,
          opened: 54321,
          clicked: 9876,
          bounced: 900,
          complained: 21,
          rates: { delivery: '99.2', open: '45.7', click: '8.3', bounce: '0.8', complaint: '0.02' },
        },
        domains: { total: 6, verified: 5, pending: 1, failed: 0 },
        suppressions: { total: 1321, bounces: 900, complaints: 21, unsubscribes: 350, manual: 50 },
        health: { score: 94, grade: 'A' },
      },
    };
  }
  if (pathname === '/v1/analytics/volume') {
    return {
      volume: [
        { date: '2025-01-01', sent: 3600, delivered: 3550, bounced: 50 },
        { date: '2025-01-06', sent: 4100, delivered: 4040, bounced: 60 },
      ],
    };
  }
  if (pathname === '/v1/analytics/engagement') {
    return {
      engagement: [
        { date: '2025-01-01', opens: 1200, clicks: 160 },
        { date: '2025-01-06', opens: 1500, clicks: 210 },
      ],
    };
  }
  if (pathname === '/v1/messages') return { messages: [] };
  if (pathname === '/v1/campaigns') return { campaigns: [] };
  if (pathname === '/v1/contacts') return { contacts: [] };
  if (pathname === '/v1/lists') return { lists: [] };
  if (pathname === '/v1/templates') return { templates: [] };
  if (pathname === '/v1/events/lists') return { lists: [] };
  if (pathname === '/v1/billing/payg/usage') return { usage: { monthToDate: 0, projected: 0 } };

  return null;
}

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url || '/', `http://127.0.0.1:${port}`);
  const body = route(requestUrl.pathname);
  if (body) {
    return json(res, 200, body);
  }
  return json(res, 404, { error: 'not_found', path: requestUrl.pathname });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`[mock-api] listening on http://127.0.0.1:${port}`);
});
