/** 
 * Settings Backup - Manage backup and DR testing
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/settings/backup');
export const POST = (r: Request) => proxyToRust(r, '/v1/admin/settings/backup');
