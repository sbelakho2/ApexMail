/** @migration Proxied to Rust: /v1/admin/compliance (was 147 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/compliance');
