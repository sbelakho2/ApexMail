/**
 * Autopilot Console API
 *
 * Proxied to Rust control-plane service which forwards to the
 * Sales Autopilot operator/loop endpoints.
 */

import { proxyToRust } from '@/lib/rust-api';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    return proxyToRust(request, '/v1/admin/autopilot');
}

export async function POST(request: Request) {
    return proxyToRust(request, '/v1/admin/autopilot');
}
