/** 
 * Run Backup Now - Trigger immediate backup
 */
import { proxyToRust } from '@/lib/rust-api';

export const POST = (r: Request) => proxyToRust(r, '/v1/admin/settings/backup/run');
