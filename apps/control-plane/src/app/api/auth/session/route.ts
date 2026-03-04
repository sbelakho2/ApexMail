/**
 * Control Plane Session API Route
 *
 * Proxied to Rust control-plane service — session validation and
 * role/name extraction now handled server-side in Rust.
 */

import { proxyToRust } from '@/lib/rust-api';

export async function GET(request: Request) {
    return proxyToRust(request, '/v1/admin/auth/session');
}
