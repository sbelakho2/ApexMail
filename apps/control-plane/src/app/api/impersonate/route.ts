/** @migration Proxied to Rust: /v1/impersonate */
import { proxyToRust } from '@/lib/rust-api';
export const POST = (r: Request) => proxyToRust(r, '/v1/impersonate');
