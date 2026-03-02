/** @migration Proxied to Rust: /v1/admin/inbox (was 148 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/inbox');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/inbox');
