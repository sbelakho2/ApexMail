/**
 * Control Plane Login API Route
 *
 * SECURITY: This authenticates platform OWNERS only, NOT customers.
 *
 * Proxied to Rust control-plane service — all authentication logic
 * (bcrypt verification, MFA, rate limiting, session creation, audit logging)
 * is now handled server-side in Rust.
 */

import { proxyToRust } from '@/lib/rust-api';

export async function POST(request: Request) {
    return proxyToRust(request, '/v1/admin/auth/login');
}
