/**
 * CSRF token endpoint
 */

import { buildCsrfResponse } from '@/lib/csrf';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
    return buildCsrfResponse(request);
}
