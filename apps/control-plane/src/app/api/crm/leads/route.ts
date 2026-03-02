import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
