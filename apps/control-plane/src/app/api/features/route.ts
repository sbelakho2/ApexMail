/** @migration Proxied to Rust: /v1/admin/features (was 172 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/features');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/features');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/features');
export const DELETE = (r: Request) => proxyToRust(r, '/v1/admin/features');
