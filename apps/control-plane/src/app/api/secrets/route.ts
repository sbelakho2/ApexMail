import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// TODO: Replace with DB query against secrets/credentials vault
const DEMO_SECRETS = [
    { id: '1', name: 'STRIPE_SECRET_KEY', type: 'api_key', description: 'Stripe payment processing', createdAt: '2024-01-15T00:00:00Z', lastRotated: '2024-11-01T00:00:00Z', expiresAt: '2025-11-01T00:00:00Z', rotationPolicy: '90d', status: 'active', accessCount: 15420, lastAccessed: new Date(1737000000000 - 300000).toISOString() },
    { id: '2', name: 'DATABASE_URL', type: 'database', description: 'Primary PostgreSQL connection', createdAt: '2024-01-01T00:00:00Z', lastRotated: '2024-12-01T00:00:00Z', expiresAt: null, rotationPolicy: 'manual', status: 'active', accessCount: 892341, lastAccessed: new Date(1737000000000 - 60000).toISOString() },
    { id: '3', name: 'GOOGLE_OAUTH_SECRET', type: 'oauth', description: 'Google Calendar integration', createdAt: '2024-03-10T00:00:00Z', lastRotated: '2024-09-10T00:00:00Z', expiresAt: '2025-01-10T00:00:00Z', rotationPolicy: '60d', status: 'expiring_soon', accessCount: 2341, lastAccessed: new Date(1737000000000 - 3600000).toISOString() },
    { id: '4', name: 'TLS_CERTIFICATE', type: 'certificate', description: 'Main domain TLS cert', createdAt: '2024-06-01T00:00:00Z', lastRotated: '2024-06-01T00:00:00Z', expiresAt: '2025-06-01T00:00:00Z', rotationPolicy: 'never', status: 'active', accessCount: 0, lastAccessed: '2024-06-01T00:00:00Z' },
    { id: '5', name: 'ENCRYPTION_KEY', type: 'encryption', description: 'Data at rest encryption', createdAt: '2024-01-01T00:00:00Z', lastRotated: '2024-10-01T00:00:00Z', expiresAt: null, rotationPolicy: '90d', status: 'active', accessCount: 423891, lastAccessed: new Date(1737000000000 - 120000).toISOString() },
    { id: '6', name: 'SENDGRID_API_KEY_OLD', type: 'api_key', description: 'Legacy SendGrid key (deprecated)', createdAt: '2023-06-01T00:00:00Z', lastRotated: '2023-06-01T00:00:00Z', expiresAt: '2024-06-01T00:00:00Z', rotationPolicy: 'never', status: 'revoked', accessCount: 0, lastAccessed: '2024-05-15T00:00:00Z' },
];

export async function GET() {
    try {
        // TODO: Query credentials vault / secrets table
        return NextResponse.json(DEMO_SECRETS);
    } catch {
        return NextResponse.json(DEMO_SECRETS);
    }
}

/**
 * POST /api/secrets — Create a new secret
 */
export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { name, type, description, rotationPolicy } = body as {
            name: string; type: string; description: string; rotationPolicy: string;
        };

        if (!name || !type) {
            return NextResponse.json({ error: 'Name and type are required' }, { status: 400 });
        }

        const newSecret = {
            id: `secret-${Date.now()}`,
            name,
            type,
            description: description || '',
            createdAt: new Date().toISOString(),
            lastRotated: new Date().toISOString(),
            expiresAt: null,
            rotationPolicy: rotationPolicy || 'manual',
            status: 'active',
            accessCount: 0,
            lastAccessed: new Date().toISOString(),
        };

        // TODO: Persist to secrets vault / database
        // For now, return the created secret (client will add to local state)
        return NextResponse.json(newSecret, { status: 201 });
    } catch (error) {
        console.error('Secrets POST error:', error);
        return NextResponse.json({ error: 'Failed to create secret' }, { status: 500 });
    }
}

/**
 * PATCH /api/secrets — Rotate or update a secret
 */
export async function PATCH(request: Request) {
    try {
        const body = await request.json();
        const { id, action } = body as { id: string; action: 'rotate' | 'revoke' };

        if (!id || !action) {
            return NextResponse.json({ error: 'Secret ID and action are required' }, { status: 400 });
        }

        if (action === 'rotate') {
            // TODO: Trigger actual key rotation in vault
            return NextResponse.json({
                success: true,
                message: `Secret ${id} rotated`,
                lastRotated: new Date().toISOString(),
                status: 'active',
            });
        }

        if (action === 'revoke') {
            // TODO: Revoke in vault
            return NextResponse.json({
                success: true,
                message: `Secret ${id} revoked`,
                status: 'revoked',
            });
        }

        return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    } catch (error) {
        console.error('Secrets PATCH error:', error);
        return NextResponse.json({ error: 'Failed to update secret' }, { status: 500 });
    }
}

/**
 * DELETE /api/secrets — Delete a secret
 */
export async function DELETE(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const id = searchParams.get('id');

        if (!id) {
            return NextResponse.json({ error: 'Secret ID is required' }, { status: 400 });
        }

        // TODO: Delete from vault
        return NextResponse.json({ success: true, message: `Secret ${id} deleted` });
    } catch (error) {
        console.error('Secrets DELETE error:', error);
        return NextResponse.json({ error: 'Failed to delete secret' }, { status: 500 });
    }
}
