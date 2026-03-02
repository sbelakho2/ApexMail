/** @migration Proxied to Rust: /v1/admin/secrets (was 194 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/secrets');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/secrets');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/secrets');
export const DELETE = (r: Request) => proxyToRust(r, '/v1/admin/secrets');
