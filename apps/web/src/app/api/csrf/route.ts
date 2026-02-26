/**
 * CSRF token endpoint
 */

import { buildCsrfResponse } from '@/lib/csrf';

export async function GET() {
    return await buildCsrfResponse();
}
