/** 
 * Integration by ID - Configure/update specific integration
 */
import { NextResponse } from 'next/server';
import { proxyToRust } from '@/lib/rust-api';

const SAFE_ID = /^[a-zA-Z0-9._:-]+$/;

function validateId(id: string) {
    if (!SAFE_ID.test(id)) return NextResponse.json({ error: 'Invalid id' }, { status: 400 });
    return null;
}

export const GET = (r: Request, { params }: { params: { id: string } }) => 
    validateId(params.id) ?? proxyToRust(r, `/v1/admin/integrations/${params.id}`);

export const POST = (r: Request, { params }: { params: { id: string } }) => 
    validateId(params.id) ?? proxyToRust(r, `/v1/admin/integrations/${params.id}`);

export const PUT = (r: Request, { params }: { params: { id: string } }) => 
    validateId(params.id) ?? proxyToRust(r, `/v1/admin/integrations/${params.id}`);

export const DELETE = (r: Request, { params }: { params: { id: string } }) => 
    validateId(params.id) ?? proxyToRust(r, `/v1/admin/integrations/${params.id}`);
