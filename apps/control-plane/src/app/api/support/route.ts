import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/support');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/support');
export const PUT = (r: Request) => proxyToRust(r, '/v1/admin/support');
