/** @migration Proxied to Rust: /v1/admin/sales/leads/update */
import { proxyToRust } from '@/lib/rust-api';
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/sales/leads/update');
