/** @migration Proxied to Rust: /v1/admin/risk (was 213 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/risk');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/risk');
