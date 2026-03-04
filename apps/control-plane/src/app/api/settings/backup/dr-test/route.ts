/** 
 * DR Failover Test - Test disaster recovery failover
 */
import { proxyToRust } from '@/lib/rust-api';

export const POST = (r: Request) => proxyToRust(r, '/v1/admin/settings/backup/dr-test');
