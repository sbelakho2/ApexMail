/** @migration Proxied to Rust: /v1/admin/sales/campaigns */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/sales/campaigns');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/sales/campaigns');
