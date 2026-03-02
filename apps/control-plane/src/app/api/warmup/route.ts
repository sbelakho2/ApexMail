/** @migration Proxied to Rust: /v1/admin/warmup (was 258 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/warmup');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/warmup');
