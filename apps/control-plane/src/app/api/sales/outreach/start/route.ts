/** @migration Proxied to Rust: /v1/admin/sales/outreach/start */
import { proxyToRust } from '@/lib/rust-api';
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/sales/outreach/start');
