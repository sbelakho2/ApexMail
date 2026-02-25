/**
 * @apexmail/testing - E2E Global Setup
 * 
 * Runs before all Playwright tests to set up the test environment.
 */

import { FullConfig } from '@playwright/test';

async function globalSetup(_config: FullConfig) {
    console.log('🌍 Global setup starting...');
    
    // Set test environment
    process.env.NODE_ENV = 'test';
    
    // Wait for services to be ready
    await waitForServices();
    
    // Seed test data
    await seedTestData();
    
    console.log('✅ Global setup complete');
}

/**
 * Wait for required services to be available
 */
async function waitForServices(): Promise<void> {
    const services = [
        { name: 'Web App', url: process.env.BASE_URL || 'http://localhost:3000' },
        { name: 'API Gateway', url: process.env.API_URL || 'http://localhost:3001' },
    ];
    
    const maxRetries = 30;
    const retryDelay = 1000;
    
    for (const service of services) {
        console.log(`  ⏳ Waiting for ${service.name}...`);
        
        let ready = false;
        for (let i = 0; i < maxRetries; i++) {
            try {
                const response = await fetch(`${service.url}/health`, {
                    method: 'GET',
                    signal: AbortSignal.timeout(5000),
                });
                
                if (response.ok) {
                    ready = true;
                    console.log(`  ✓ ${service.name} is ready`);
                    break;
                }
            } catch {
                // Service not ready yet
            }
            
            await new Promise((resolve) => setTimeout(resolve, retryDelay));
        }
        
        if (!ready) {
            console.log(`  ⚠️ ${service.name} not available, continuing anyway...`);
        }
    }
}

/**
 * Seed test data into the database
 */
async function seedTestData(): Promise<void> {
    console.log('  📦 Seeding test data...');
    
    // In a real implementation, this would seed the database
    // with test users, campaigns, contacts, etc.
    
    const testData = {
        users: [
            {
                id: 'test-user-1',
                email: 'test@apexmail.test',
                password: process.env.E2E_TEST_USER_PASSWORD ?? 'testpassword123',
                name: 'Test User',
            },
            {
                id: 'test-admin-1',
                email: 'admin@apexmail.test',
                password: process.env.E2E_TEST_ADMIN_PASSWORD ?? 'adminpassword123',
                name: 'Test Admin',
                role: 'admin',
            },
        ],
        workspaces: [
            {
                id: 'test-workspace-1',
                name: 'Test Workspace',
                slug: 'test-workspace',
                ownerId: 'test-user-1',
            },
        ],
        campaigns: [
            {
                id: 'test-campaign-1',
                name: 'Test Campaign',
                subject: 'Test Subject Line',
                status: 'draft',
                workspaceId: 'test-workspace-1',
            },
        ],
        lists: [
            {
                id: 'test-list-1',
                name: 'Test List',
                workspaceId: 'test-workspace-1',
            },
        ],
        contacts: [
            {
                id: 'test-contact-1',
                email: 'contact1@example.com',
                firstName: 'John',
                lastName: 'Doe',
                listId: 'test-list-1',
            },
            {
                id: 'test-contact-2',
                email: 'contact2@example.com',
                firstName: 'Jane',
                lastName: 'Smith',
                listId: 'test-list-1',
            },
        ],
    };
    
    // Store in global for access in tests
    (global as Record<string, unknown>).__TEST_DATA__ = testData;
    
    console.log('  ✓ Test data seeded');
}

export default globalSetup;
