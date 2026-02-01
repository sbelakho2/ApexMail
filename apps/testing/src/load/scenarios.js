/**
 * @apexmail/testing - k6 Load Test Scenarios
 * 
 * Load testing scenarios using k6 for performance validation.
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration');
const campaignCreateDuration = new Trend('campaign_create_duration');
const contactSearchDuration = new Trend('contact_search_duration');
const apiCalls = new Counter('api_calls');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const API_URL = __ENV.API_URL || 'http://localhost:3001';

// Test configuration options
export const options = {
    scenarios: {
        // Smoke test - basic functionality check
        smoke: {
            executor: 'constant-vus',
            vus: 1,
            duration: '1m',
            tags: { test_type: 'smoke' },
            exec: 'smokeTest',
        },
        
        // Load test - normal load conditions
        load: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 50 },  // Ramp up
                { duration: '5m', target: 50 },  // Steady state
                { duration: '2m', target: 0 },   // Ramp down
            ],
            tags: { test_type: 'load' },
            exec: 'loadTest',
        },
        
        // Stress test - beyond normal capacity
        stress: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 100 },
                { duration: '5m', target: 100 },
                { duration: '2m', target: 200 },
                { duration: '5m', target: 200 },
                { duration: '2m', target: 300 },
                { duration: '5m', target: 300 },
                { duration: '5m', target: 0 },
            ],
            tags: { test_type: 'stress' },
            exec: 'stressTest',
        },
        
        // Spike test - sudden traffic spike
        spike: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '30s', target: 10 },
                { duration: '1m', target: 500 },  // Spike
                { duration: '30s', target: 10 },
                { duration: '1m', target: 500 },  // Another spike
                { duration: '30s', target: 0 },
            ],
            tags: { test_type: 'spike' },
            exec: 'spikeTest',
        },
        
        // Soak test - extended duration for memory leaks
        soak: {
            executor: 'constant-vus',
            vus: 50,
            duration: '30m',
            tags: { test_type: 'soak' },
            exec: 'soakTest',
        },
        
        // Breakpoint test - find system limits
        breakpoint: {
            executor: 'ramping-arrival-rate',
            startRate: 10,
            timeUnit: '1s',
            preAllocatedVUs: 500,
            maxVUs: 1000,
            stages: [
                { duration: '2m', target: 50 },
                { duration: '2m', target: 100 },
                { duration: '2m', target: 200 },
                { duration: '2m', target: 400 },
                { duration: '2m', target: 600 },
            ],
            tags: { test_type: 'breakpoint' },
            exec: 'breakpointTest',
        },
    },
    
    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<1000'],
        http_req_failed: ['rate<0.01'],
        errors: ['rate<0.05'],
        login_duration: ['p(95)<1000'],
        campaign_create_duration: ['p(95)<2000'],
        contact_search_duration: ['p(95)<500'],
    },
};

// Helper functions
function getAuthHeaders(token) {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
    };
}

function login() {
    const start = Date.now();
    const payload = JSON.stringify({
        email: `loadtest-${__VU}@apexmail.test`,
        password: 'TestPassword123!',
    });
    
    const response = http.post(`${API_URL}/auth/login`, payload, {
        headers: { 'Content-Type': 'application/json' },
        tags: { endpoint: 'login' },
    });
    
    loginDuration.add(Date.now() - start);
    apiCalls.add(1);
    
    const success = check(response, {
        'login successful': (r) => r.status === 200,
        'has token': (r) => r.json('token') !== undefined,
    });
    
    errorRate.add(!success);
    
    if (success) {
        return response.json('token');
    }
    return null;
}

// Smoke test scenario
export function smokeTest() {
    group('Smoke Test', () => {
        // Test health endpoint
        const healthRes = http.get(`${API_URL}/health`);
        check(healthRes, {
            'health check passed': (r) => r.status === 200,
        });
        
        // Test login
        const token = login();
        if (!token) return;
        
        // Test dashboard API
        const dashboardRes = http.get(`${API_URL}/dashboard/stats`, {
            headers: getAuthHeaders(token),
        });
        check(dashboardRes, {
            'dashboard stats loaded': (r) => r.status === 200,
        });
        
        sleep(1);
    });
}

// Load test scenario
export function loadTest() {
    const token = login();
    if (!token) {
        sleep(1);
        return;
    }
    
    group('Dashboard', () => {
        const res = http.get(`${API_URL}/dashboard/stats`, {
            headers: getAuthHeaders(token),
            tags: { endpoint: 'dashboard' },
        });
        
        check(res, {
            'dashboard loaded': (r) => r.status === 200,
        });
        apiCalls.add(1);
        
        sleep(randomIntBetween(1, 3));
    });
    
    group('Campaigns', () => {
        // List campaigns
        const listRes = http.get(`${API_URL}/campaigns?page=1&limit=20`, {
            headers: getAuthHeaders(token),
            tags: { endpoint: 'campaigns_list' },
        });
        
        check(listRes, {
            'campaigns listed': (r) => r.status === 200,
        });
        apiCalls.add(1);
        
        sleep(randomIntBetween(1, 2));
        
        // Create campaign
        if (Math.random() < 0.3) {
            const start = Date.now();
            const createRes = http.post(
                `${API_URL}/campaigns`,
                JSON.stringify({
                    name: `Load Test Campaign ${randomString(8)}`,
                    subject: 'Test Subject Line',
                    content: '<p>Test email content</p>',
                }),
                {
                    headers: getAuthHeaders(token),
                    tags: { endpoint: 'campaigns_create' },
                }
            );
            
            campaignCreateDuration.add(Date.now() - start);
            apiCalls.add(1);
            
            check(createRes, {
                'campaign created': (r) => r.status === 201,
            });
        }
        
        sleep(randomIntBetween(1, 3));
    });
    
    group('Contacts', () => {
        // List contacts
        const listRes = http.get(`${API_URL}/contacts?page=1&limit=50`, {
            headers: getAuthHeaders(token),
            tags: { endpoint: 'contacts_list' },
        });
        
        check(listRes, {
            'contacts listed': (r) => r.status === 200,
        });
        apiCalls.add(1);
        
        // Search contacts
        if (Math.random() < 0.5) {
            const start = Date.now();
            const searchRes = http.get(`${API_URL}/contacts/search?q=test`, {
                headers: getAuthHeaders(token),
                tags: { endpoint: 'contacts_search' },
            });
            
            contactSearchDuration.add(Date.now() - start);
            apiCalls.add(1);
            
            check(searchRes, {
                'search completed': (r) => r.status === 200,
            });
        }
        
        sleep(randomIntBetween(1, 2));
    });
}

// Stress test scenario
export function stressTest() {
    const token = login();
    if (!token) {
        errorRate.add(true);
        sleep(0.5);
        return;
    }
    
    // Rapid-fire API calls to stress the system
    for (let i = 0; i < 5; i++) {
        const res = http.get(`${API_URL}/campaigns`, {
            headers: getAuthHeaders(token),
            tags: { endpoint: 'campaigns', test: 'stress' },
        });
        
        const success = check(res, {
            'request successful': (r) => r.status === 200,
            'response time OK': (r) => r.timings.duration < 2000,
        });
        
        errorRate.add(!success);
        apiCalls.add(1);
        
        sleep(0.1);
    }
    
    sleep(randomIntBetween(0, 1));
}

// Spike test scenario
export function spikeTest() {
    const token = login();
    if (!token) {
        errorRate.add(true);
        return;
    }
    
    // Simulated user journey under spike
    const endpoints = [
        '/dashboard/stats',
        '/campaigns',
        '/contacts',
        '/analytics/overview',
    ];
    
    for (const endpoint of endpoints) {
        const res = http.get(`${API_URL}${endpoint}`, {
            headers: getAuthHeaders(token),
            tags: { endpoint: endpoint.replace('/', ''), test: 'spike' },
        });
        
        const success = check(res, {
            'spike request handled': (r) => r.status === 200 || r.status === 429,
        });
        
        errorRate.add(r.status >= 500);
        apiCalls.add(1);
        
        sleep(0.1);
    }
}

// Soak test scenario
export function soakTest() {
    const token = login();
    if (!token) {
        errorRate.add(true);
        sleep(5);
        return;
    }
    
    // Typical user workflow repeated over extended period
    group('Extended Session', () => {
        // Dashboard check
        http.get(`${API_URL}/dashboard/stats`, {
            headers: getAuthHeaders(token),
            tags: { test: 'soak' },
        });
        apiCalls.add(1);
        
        sleep(randomIntBetween(5, 10));
        
        // Browse campaigns
        http.get(`${API_URL}/campaigns?page=1`, {
            headers: getAuthHeaders(token),
            tags: { test: 'soak' },
        });
        apiCalls.add(1);
        
        sleep(randomIntBetween(5, 15));
        
        // Browse contacts
        http.get(`${API_URL}/contacts?page=1`, {
            headers: getAuthHeaders(token),
            tags: { test: 'soak' },
        });
        apiCalls.add(1);
        
        sleep(randomIntBetween(10, 20));
    });
}

// Breakpoint test scenario
export function breakpointTest() {
    // Simplified requests to find the breaking point
    const res = http.get(`${API_URL}/health`, {
        tags: { test: 'breakpoint' },
    });
    
    const success = check(res, {
        'still responding': (r) => r.status === 200,
        'acceptable latency': (r) => r.timings.duration < 5000,
    });
    
    errorRate.add(!success);
    apiCalls.add(1);
}

// Setup function - runs once before test
export function setup() {
    console.log('Setting up load test...');
    
    // Verify system is accessible
    const healthCheck = http.get(`${API_URL}/health`);
    if (healthCheck.status !== 200) {
        throw new Error('System not available for load testing');
    }
    
    // Create test users if needed
    for (let i = 1; i <= options.scenarios.stress.stages[4].target; i++) {
        http.post(
            `${API_URL}/auth/register`,
            JSON.stringify({
                email: `loadtest-${i}@apexmail.test`,
                password: 'TestPassword123!',
                name: `Load Test User ${i}`,
            }),
            { headers: { 'Content-Type': 'application/json' } }
        );
    }
    
    return { startTime: Date.now() };
}

// Teardown function - runs once after test
export function teardown(data) {
    console.log(`Load test completed. Duration: ${(Date.now() - data.startTime) / 1000}s`);
}

// Custom summary handler
export function handleSummary(data) {
    const summary = {
        timestamp: new Date().toISOString(),
        duration: data.state.testRunDurationMs,
        vus: data.metrics.vus?.values?.value || 0,
        requests: {
            total: data.metrics.http_reqs?.values?.count || 0,
            rate: data.metrics.http_reqs?.values?.rate || 0,
        },
        latency: {
            avg: data.metrics.http_req_duration?.values?.avg || 0,
            p95: data.metrics.http_req_duration?.values?.['p(95)'] || 0,
            p99: data.metrics.http_req_duration?.values?.['p(99)'] || 0,
            max: data.metrics.http_req_duration?.values?.max || 0,
        },
        errors: {
            rate: data.metrics.errors?.values?.rate || 0,
            httpFailRate: data.metrics.http_req_failed?.values?.rate || 0,
        },
        custom: {
            loginP95: data.metrics.login_duration?.values?.['p(95)'] || 0,
            campaignCreateP95: data.metrics.campaign_create_duration?.values?.['p(95)'] || 0,
            contactSearchP95: data.metrics.contact_search_duration?.values?.['p(95)'] || 0,
            totalApiCalls: data.metrics.api_calls?.values?.count || 0,
        },
        thresholds: data.thresholds,
    };
    
    return {
        'stdout': JSON.stringify(summary, null, 2),
        'test-results/load/summary.json': JSON.stringify(summary, null, 2),
        'test-results/load/report.html': generateHtmlReport(summary),
    };
}

function generateHtmlReport(summary) {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>ApexMail Load Test Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }
        .metric { display: inline-block; padding: 20px; margin: 10px; background: #f5f5f5; border-radius: 8px; }
        .metric-value { font-size: 32px; font-weight: bold; color: #333; }
        .metric-label { font-size: 14px; color: #666; margin-top: 5px; }
        .passed { color: #22c55e; }
        .failed { color: #ef4444; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f8f8; }
    </style>
</head>
<body>
    <h1>ApexMail Load Test Report</h1>
    <p>Generated: ${summary.timestamp}</p>
    
    <h2>Overview</h2>
    <div class="metric">
        <div class="metric-value">${summary.requests.total.toLocaleString()}</div>
        <div class="metric-label">Total Requests</div>
    </div>
    <div class="metric">
        <div class="metric-value">${summary.requests.rate.toFixed(2)}/s</div>
        <div class="metric-label">Request Rate</div>
    </div>
    <div class="metric">
        <div class="metric-value">${summary.latency.p95.toFixed(0)}ms</div>
        <div class="metric-label">P95 Latency</div>
    </div>
    <div class="metric">
        <div class="metric-value ${summary.errors.rate < 0.05 ? 'passed' : 'failed'}">${(summary.errors.rate * 100).toFixed(2)}%</div>
        <div class="metric-label">Error Rate</div>
    </div>
    
    <h2>Latency Breakdown</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Average</td><td>${summary.latency.avg.toFixed(2)}ms</td></tr>
        <tr><td>P95</td><td>${summary.latency.p95.toFixed(2)}ms</td></tr>
        <tr><td>P99</td><td>${summary.latency.p99.toFixed(2)}ms</td></tr>
        <tr><td>Max</td><td>${summary.latency.max.toFixed(2)}ms</td></tr>
    </table>
    
    <h2>Custom Metrics</h2>
    <table>
        <tr><th>Metric</th><th>P95</th></tr>
        <tr><td>Login Duration</td><td>${summary.custom.loginP95.toFixed(2)}ms</td></tr>
        <tr><td>Campaign Create</td><td>${summary.custom.campaignCreateP95.toFixed(2)}ms</td></tr>
        <tr><td>Contact Search</td><td>${summary.custom.contactSearchP95.toFixed(2)}ms</td></tr>
    </table>
    
    <h2>Threshold Results</h2>
    <table>
        <tr><th>Threshold</th><th>Status</th></tr>
        ${Object.entries(summary.thresholds || {}).map(([name, result]) => `
            <tr>
                <td>${name}</td>
                <td class="${result.ok ? 'passed' : 'failed'}">${result.ok ? 'PASSED' : 'FAILED'}</td>
            </tr>
        `).join('')}
    </table>
</body>
</html>
    `;
}
