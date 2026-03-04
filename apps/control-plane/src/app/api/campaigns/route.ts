import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/campaigns');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/campaigns');
