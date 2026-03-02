/** @migration Proxied to Rust: /v1/admin/revenue (was 143 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/revenue');
