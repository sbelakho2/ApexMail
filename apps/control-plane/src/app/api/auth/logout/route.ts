/**
 * Control Plane Logout API Route
 *
 * Proxied to Rust control-plane service — session invalidation
 * and cookie clearing now handled server-side in Rust.
 */

import { proxyToRust } from '@/lib/rust-api';

export async function POST(request: Request) {
    return proxyToRust(request, '/v1/admin/auth/logout');
}

// FIX-500-030: GET logout removed — enables CSRF via <img src="/api/auth/logout">.
// Logout MUST be POST-only to require an intentional action.
