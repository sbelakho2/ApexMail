# Development Guide

Guide for developers contributing to ApexMail.

## Prerequisites

- **Node.js** 20.11.0 or later
- **pnpm** 8.14.0 or later
- **Docker** and Docker Compose
- **Git**

## Development Setup

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/sbelakho2/ApexMail.git
cd ApexMail

# Install dependencies
pnpm install

# Set up environment
cp .env.example .env
```

### 2. Start Infrastructure

```bash
# Start PostgreSQL, Redis, and Mailpit
docker compose up -d postgres redis mailpit
```

### 3. Initialize Database

```bash
# Run migrations
pnpm db:migrate

# Seed development data
pnpm db:seed
```

### 4. Start Development Servers

```bash
# Start all services
pnpm dev

# Or start specific services
pnpm --filter @apexmail/api dev
pnpm --filter @apexmail/web dev
```

---

## Project Structure

```
apexmail/
├── apps/
│   ├── api/                 # REST API (Hono)
│   │   ├── src/
│   │   │   ├── routes/      # API endpoints
│   │   │   ├── services/    # Business logic
│   │   │   ├── middleware/  # Request middleware
│   │   │   └── index.ts     # Entry point
│   │   └── package.json
│   │
│   ├── web/                 # Dashboard (Next.js 14)
│   │   ├── src/
│   │   │   ├── app/         # App router pages
│   │   │   ├── components/  # React components
│   │   │   ├── hooks/       # Custom hooks
│   │   │   └── lib/         # Utilities
│   │   └── package.json
│   │
│   ├── worker/              # Background jobs (BullMQ)
│   ├── mta/                 # Email server (Postfix)
│   ├── tracking/            # Open/click tracking
│   ├── analytics/           # Analytics engine
│   ├── ai/                  # AI inference
│   ├── compliance/          # Security & GDPR
│   ├── sales-autopilot/     # CRM module
│   ├── ops/                 # Operations
│   └── testing/             # Test infrastructure
│
├── packages/
│   ├── db/                  # Database layer
│   │   ├── prisma/          # Schema & migrations
│   │   └── src/             # Client & utilities
│   │
│   └── lib/                 # Shared utilities
│       ├── src/
│       │   ├── crypto/      # Encryption
│       │   ├── validation/  # Schema validation
│       │   └── utils/       # Helpers
│       └── package.json
│
├── docs/                    # Documentation
├── tools/                   # Build & dev tools
└── pnpm-workspace.yaml      # Workspace config
```

---

## Coding Standards

### TypeScript

- Strict mode enabled
- Explicit return types on functions
- No `any` types (use `unknown` if needed)
- Prefer interfaces over types for objects

```typescript
// Good
interface User {
  id: string;
  email: string;
  createdAt: Date;
}

function getUser(id: string): Promise<User | null> {
  return db.users.findUnique({ where: { id } });
}

// Bad
type User = {
  id: any;
  email: string;
}

function getUser(id) {
  return db.users.findUnique({ where: { id } });
}
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Variables | camelCase | `userName` |
| Functions | camelCase | `getUserById()` |
| Classes | PascalCase | `UserService` |
| Interfaces | PascalCase | `UserProfile` |
| Constants | SCREAMING_SNAKE | `MAX_RETRIES` |
| Files | kebab-case | `user-service.ts` |
| Directories | kebab-case | `email-sending/` |

### File Organization

```typescript
// 1. Imports (external, internal, relative)
import { z } from 'zod';
import { db } from '@apexmail/db';
import { logger } from '../lib/logger';

// 2. Types/Interfaces
interface CreateUserInput {
  email: string;
  name: string;
}

// 3. Constants
const MAX_NAME_LENGTH = 100;

// 4. Main exports
export class UserService {
  // ...
}

// 5. Helper functions (private)
function validateEmail(email: string): boolean {
  // ...
}
```

### Error Handling

```typescript
// Define custom errors
class NotFoundError extends Error {
  constructor(resource: string, id: string) {
    super(`${resource} with id ${id} not found`);
    this.name = 'NotFoundError';
  }
}

// Use Result types for expected failures
type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E };

async function getUser(id: string): Promise<Result<User, NotFoundError>> {
  const user = await db.users.findUnique({ where: { id } });
  
  if (!user) {
    return { success: false, error: new NotFoundError('User', id) };
  }
  
  return { success: true, data: user };
}
```

---

## Testing

### Test Structure

```
apps/api/
├── src/
│   └── services/
│       └── user-service.ts
└── tests/
    ├── unit/
    │   └── services/
    │       └── user-service.test.ts
    ├── integration/
    │   └── api/
    │       └── users.test.ts
    └── e2e/
        └── user-flow.spec.ts
```

### Running Tests

```bash
# Run all tests
pnpm test

# Run specific package tests
pnpm --filter @apexmail/api test

# Run with coverage
pnpm test:coverage

# Run in watch mode
pnpm test:watch
```

### Writing Tests

```typescript
// Unit test example
import { describe, it, expect, vi } from 'vitest';
import { UserService } from '../src/services/user-service';

describe('UserService', () => {
  describe('createUser', () => {
    it('should create a user with valid input', async () => {
      const mockDb = {
        users: {
          create: vi.fn().mockResolvedValue({
            id: 'usr_123',
            email: 'test@example.com',
          }),
        },
      };
      
      const service = new UserService(mockDb);
      const result = await service.createUser({
        email: 'test@example.com',
        name: 'Test User',
      });
      
      expect(result.success).toBe(true);
      expect(result.data.email).toBe('test@example.com');
    });
    
    it('should reject invalid email', async () => {
      const service = new UserService(mockDb);
      const result = await service.createUser({
        email: 'invalid',
        name: 'Test',
      });
      
      expect(result.success).toBe(false);
      expect(result.error.code).toBe('INVALID_EMAIL');
    });
  });
});
```

### Integration Tests

```typescript
// Integration test example
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestClient } from '../helpers/test-client';

describe('Users API', () => {
  let client: TestClient;
  
  beforeAll(async () => {
    client = await createTestClient();
  });
  
  afterAll(async () => {
    await client.cleanup();
  });
  
  it('POST /api/v1/users creates a user', async () => {
    const response = await client.post('/api/v1/users', {
      email: 'new@example.com',
      name: 'New User',
    });
    
    expect(response.status).toBe(201);
    expect(response.body.email).toBe('new@example.com');
  });
});
```

---

## Database

### Migrations

```bash
# Create a new migration
pnpm db:migrate:create add_user_preferences

# Run migrations
pnpm db:migrate

# Reset database (development only)
pnpm db:reset

# Open Prisma Studio
pnpm db:studio
```

### Writing Migrations

```typescript
// packages/db/prisma/migrations/20240115_add_user_preferences/migration.sql
-- CreateTable
CREATE TABLE "user_preferences" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "theme" TEXT NOT NULL DEFAULT 'light',
    "timezone" TEXT NOT NULL DEFAULT 'UTC',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_preferences_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_preferences_user_id_key" ON "user_preferences"("user_id");

-- AddForeignKey
ALTER TABLE "user_preferences" ADD CONSTRAINT "user_preferences_user_id_fkey" 
FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
```

### Database Queries

```typescript
// Use the repository pattern
import { db } from '@apexmail/db';

// Simple query
const user = await db.users.findUnique({
  where: { id: userId },
});

// With relations
const userWithMessages = await db.users.findUnique({
  where: { id: userId },
  include: {
    messages: {
      take: 10,
      orderBy: { createdAt: 'desc' },
    },
  },
});

// Transaction
await db.$transaction(async (tx) => {
  const user = await tx.users.create({ data: userData });
  await tx.accounts.create({ data: { userId: user.id, ...accountData } });
});
```

---

## API Development

### Creating Routes

```typescript
// apps/api/src/routes/users.ts
import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '../middleware/auth';
import { UserService } from '../services/user-service';

const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
});

const usersRouter = new Hono()
  .use('*', authMiddleware)
  .post(
    '/',
    zValidator('json', createUserSchema),
    async (c) => {
      const data = c.req.valid('json');
      const service = new UserService();
      const result = await service.createUser(data);
      
      if (!result.success) {
        return c.json({ error: result.error }, 400);
      }
      
      return c.json(result.data, 201);
    }
  )
  .get('/:id', async (c) => {
    const id = c.req.param('id');
    const service = new UserService();
    const result = await service.getUser(id);
    
    if (!result.success) {
      return c.json({ error: result.error }, 404);
    }
    
    return c.json(result.data);
  });

export { usersRouter };
```

### Middleware

```typescript
// apps/api/src/middleware/auth.ts
import { createMiddleware } from 'hono/factory';
import { verifyToken } from '../lib/jwt';

export const authMiddleware = createMiddleware(async (c, next) => {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  const token = authHeader.slice(7);
  const payload = await verifyToken(token);
  
  if (!payload) {
    return c.json({ error: 'Invalid token' }, 401);
  }
  
  c.set('user', payload);
  await next();
});
```

---

## Git Workflow

### Branch Naming

```
feature/add-email-scheduling
bugfix/fix-bounce-handling
hotfix/security-vulnerability
docs/update-api-reference
refactor/improve-queue-performance
```

### Commit Messages

Follow Conventional Commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(api): add email scheduling endpoint

Add POST /api/v1/messages/schedule endpoint for delayed sending.
Includes validation for future timestamps.

Closes #123

---

fix(worker): handle Redis connection failures

Implement exponential backoff for Redis reconnection.
Add circuit breaker to prevent cascade failures.
```

### Pull Request Process

1. Create feature branch from `main`
2. Make changes with clear commits
3. Run tests locally: `pnpm test`
4. Run linting: `pnpm lint`
5. Open PR with description
6. Address review comments
7. Squash and merge

---

## Debugging

### Logging

```typescript
import { logger } from '@apexmail/lib';

// Log levels
logger.debug('Detailed debugging info', { context });
logger.info('General information', { userId });
logger.warn('Warning message', { issue });
logger.error('Error occurred', { error, stack: error.stack });
```

### Debug Mode

```bash
# Enable debug logging
DEBUG=apexmail:* pnpm dev

# Specific namespaces
DEBUG=apexmail:api:* pnpm dev
DEBUG=apexmail:worker:* pnpm dev
```

### VS Code Configuration

```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug API",
      "cwd": "${workspaceFolder}/apps/api",
      "runtimeExecutable": "pnpm",
      "runtimeArgs": ["dev"],
      "skipFiles": ["<node_internals>/**"]
    }
  ]
}
```

---

## Common Tasks

### Add a New Package

```bash
# Create package directory
mkdir -p packages/new-package/src

# Initialize package.json
cat > packages/new-package/package.json << EOF
{
  "name": "@apexmail/new-package",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch"
  }
}
EOF

# Add to workspace
pnpm install
```

### Add a Dependency

```bash
# Add to specific package
pnpm --filter @apexmail/api add zod

# Add dev dependency
pnpm --filter @apexmail/api add -D vitest

# Add to all packages
pnpm add -w typescript
```

### Update Dependencies

```bash
# Check for updates
pnpm outdated

# Update all
pnpm update

# Update specific package
pnpm --filter @apexmail/api update zod
```
