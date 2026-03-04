/** @migration Proxied to Rust: /v1/admin/content (was 70 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/content');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/content');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/content');
export const DELETE = (r: Request) => proxyToRust(r, '/v1/admin/content');
