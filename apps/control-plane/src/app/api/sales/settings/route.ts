/** @migration Proxied to Rust: /v1/admin/sales/settings */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/sales/settings');
export const PUT = (r: Request) => proxyToRust(r, '/v1/admin/sales/settings');
