/** 
 * Analytics Platform Metrics - Platform-wide analytics for owner dashboard
 */
import { proxyToRust } from '@/lib/rust-api';

export const GET = (r: Request) => proxyToRust(r, '/v1/admin/analytics/platform');
