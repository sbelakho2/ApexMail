import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
export const PATCH = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
export const DELETE = (r: Request) => proxyToRust(r, '/v1/admin/crm/leads');
