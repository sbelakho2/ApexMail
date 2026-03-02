/** @migration Proxied to Rust: /v1/admin/gdpr (was 112 lines) */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/gdpr');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/gdpr');
