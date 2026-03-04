/**
 * Audit Export Job Status - Poll export job progress by ID
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request, { params }: { params: { id: string } }) =>
    proxyToRust(r, `/v1/admin/audit/export/${encodeURIComponent(params.id)}`);
