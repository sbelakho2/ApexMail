/**
 * Operator Settings API - GET/PUT platform settings
 */
import { proxyToRust } from '@/lib/rust-api';
export const GET = (r: Request) => proxyToRust(r, '/v1/operator/settings');
export const PUT = (r: Request) => proxyToRust(r, '/v1/operator/settings');
