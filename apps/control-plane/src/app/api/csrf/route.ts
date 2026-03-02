/** @migration Proxied to Rust: /v1/csrf */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/csrf');
