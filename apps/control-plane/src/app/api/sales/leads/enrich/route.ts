/** @migration Proxied to Rust: /v1/admin/sales/leads/enrich */
import { proxyToRust } from '@/lib/rust-api';
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/sales/leads/enrich');
