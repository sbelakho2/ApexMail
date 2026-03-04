/**
 * IP Warmup advance all IPs to next day
 */
import { proxyToRust } from '@/lib/rust-api';

export const POST = (r: Request) => proxyToRust(r, '/v1/admin/warmup/advance');
