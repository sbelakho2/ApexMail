/**
 * 5-Minute Activation Path
 *
 * Guides new users from sign-up to first successful email send
 * in under 5 minutes. Tracks progress, provides contextual help,
 * and reports activation metrics to the funnel tracker.
 *
 * Steps:
 *   1. Create API key           (~30 seconds)
 *   2. Install SDK               (~60 seconds)
 *   3. Send test email           (~60 seconds)
 *   4. Verify domain (optional)  (~120 seconds active, 24-48h propagation)
 *   5. Set up webhook            (~60 seconds)
 *
 * The path is progressive: step 3 (first send) is the "aha moment".
 * Steps 4-5 are post-activation hardening.
 */

import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'activation-path', level: 'info' });

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface ActivationStep {
    id: ActivationStepId;
    order: number;
    title: string;
    description: string;
    estimatedSeconds: number;
    required: boolean;
    /** Shell / code snippet the user can copy-paste */
    codeSnippet: CodeSnippet[];
    /** How to programmatically verify this step is complete */
    verificationHint: string;
    /** Help text shown if the step is taking longer than expected */
    troubleshooting: string[];
}

export type ActivationStepId =
    | 'create_api_key'
    | 'install_sdk'
    | 'send_test_email'
    | 'verify_domain'
    | 'setup_webhook';

export interface CodeSnippet {
    language: string;
    label: string;
    code: string;
}

export interface ActivationProgress {
    userId: string;
    tenantId: string;
    steps: Record<ActivationStepId, StepStatus>;
    startedAt: Date;
    activatedAt: Date | null; // set when send_test_email completes
    completedAt: Date | null; // set when all required steps done
}

export interface StepStatus {
    status: 'not_started' | 'in_progress' | 'completed' | 'skipped';
    startedAt: Date | null;
    completedAt: Date | null;
    durationMs: number | null;
}

// ────────────────────────────────────────────────────────────────────
// Step Definitions
// ────────────────────────────────────────────────────────────────────

export const ACTIVATION_STEPS: ActivationStep[] = [
    {
        id: 'create_api_key',
        order: 1,
        title: 'Create your API key',
        description: 'Generate an API key from the dashboard. This is the credential your application uses to authenticate with ApexMail.',
        estimatedSeconds: 30,
        required: true,
        codeSnippet: [],
        verificationHint: 'Check if the tenant has at least one active API key.',
        troubleshooting: [
            'Make sure you copy the full key — it\'s only shown once.',
            'If you accidentally close the dialog, revoke the key and create a new one.',
        ],
    },
    {
        id: 'install_sdk',
        order: 2,
        title: 'Install the SDK',
        description: 'Add the ApexMail SDK to your project. We support Node.js, Python, Go, Ruby, and any language via REST.',
        estimatedSeconds: 60,
        required: true,
        codeSnippet: [
            {
                language: 'bash',
                label: 'Node.js',
                code: 'npm install @apexmail/sdk',
            },
            {
                language: 'bash',
                label: 'Python',
                code: 'pip install apexmail',
            },
            {
                language: 'bash',
                label: 'cURL (no SDK needed)',
                code: `curl -X POST https://api.apexmail.ee/v1/messages \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "from": "test@yourdomain.com",
    "to": "you@example.com",
    "subject": "Hello from ApexMail",
    "html": "<p>It works!</p>"
  }'`,
            },
        ],
        verificationHint: 'First API call received from this tenant.',
        troubleshooting: [
            'If npm install fails, check that you\'re using Node.js 18+.',
            'For Python, use a virtual environment to avoid permission issues.',
        ],
    },
    {
        id: 'send_test_email',
        order: 3,
        title: 'Send your first email',
        description: 'Send a test email to yourself. This is the "aha moment" — seeing an email land in your inbox via ApexMail.',
        estimatedSeconds: 60,
        required: true,
        codeSnippet: [
            {
                language: 'typescript',
                label: 'Node.js',
                code: `import { ApexMail } from '@apexmail/sdk';

const apexmail = new ApexMail(process.env.APEXMAIL_API_KEY!);

const result = await apexmail.messages.send({
  from: 'hello@yourdomain.com',
  to: 'you@example.com',
  subject: 'My first ApexMail email',
  html: '<h1>It works! 🎉</h1><p>This email was sent via ApexMail.</p>',
});

console.log('Sent!', result.id);`,
            },
            {
                language: 'python',
                label: 'Python',
                code: `import apexmail
import os

client = apexmail.Client(api_key=os.environ["APEXMAIL_API_KEY"])

result = client.messages.send(
    from_email="hello@yourdomain.com",
    to="you@example.com",
    subject="My first ApexMail email",
    html="<h1>It works! 🎉</h1><p>This email was sent via ApexMail.</p>",
)

print(f"Sent! {result.id}")`,
            },
        ],
        verificationHint: 'Check for first_successful_send event from this tenant.',
        troubleshooting: [
            'If you get AUTH_001, double-check your API key has no leading/trailing whitespace.',
            'If you get DOM_001, you can use the sandbox domain for testing.',
            'Check your spam folder — the first email from an unverified domain may be filtered.',
        ],
    },
    {
        id: 'verify_domain',
        order: 4,
        title: 'Verify your sending domain',
        description: 'Add SPF, DKIM, and DMARC records so your emails land in the inbox instead of spam. This is the most important step for production use.',
        estimatedSeconds: 120,
        required: false, // not required for activation, but strongly recommended
        codeSnippet: [
            {
                language: 'bash',
                label: 'Verify DNS records',
                code: `# Check SPF
dig TXT yourdomain.com | grep spf

# Check DKIM
dig CNAME am._domainkey.yourdomain.com

# Check DMARC
dig TXT _dmarc.yourdomain.com`,
            },
        ],
        verificationHint: 'Domain status = verified in the domains table.',
        troubleshooting: [
            'DNS propagation can take up to 48 hours. Be patient.',
            'Only one SPF record is allowed per domain — merge includes.',
            'Some DNS providers don\'t support CNAME at the apex. Use a subdomain.',
        ],
    },
    {
        id: 'setup_webhook',
        order: 5,
        title: 'Set up a webhook',
        description: 'Receive real-time notifications when emails are delivered, opened, clicked, or bounce. This closes the feedback loop.',
        estimatedSeconds: 60,
        required: false,
        codeSnippet: [
            {
                language: 'typescript',
                label: 'Express.js webhook handler',
                code: `import express from 'express';

const app = express();
app.use(express.json());

app.post('/webhooks/apexmail', (req, res) => {
  const event = req.body;
  
  switch (event.type) {
    case 'email.delivered':
      console.log('Delivered to', event.data.to);
      break;
    case 'email.opened':
      console.log('Opened by', event.data.to);
      break;
    case 'email.bounced':
      console.log('Bounced:', event.data.bounce_type);
      break;
  }
  
  res.status(200).json({ received: true });
});

app.listen(3000);`,
            },
        ],
        verificationHint: 'Webhook endpoint registered and first event delivered.',
        troubleshooting: [
            'Make sure your endpoint returns 2xx within 5 seconds.',
            'Use a tool like ngrok for local development.',
            'Check webhook logs in the dashboard for delivery failures.',
        ],
    },
];

// ────────────────────────────────────────────────────────────────────
// Activation Tracker
// ────────────────────────────────────────────────────────────────────

export class ActivationTracker {
    private progress = new Map<string, ActivationProgress>();

    initUser(userId: string, tenantId: string): ActivationProgress {
        const steps: Record<ActivationStepId, StepStatus> = {} as any;
        for (const step of ACTIVATION_STEPS) {
            steps[step.id] = {
                status: 'not_started',
                startedAt: null,
                completedAt: null,
                durationMs: null,
            };
        }

        const progress: ActivationProgress = {
            userId,
            tenantId,
            steps,
            startedAt: new Date(),
            activatedAt: null,
            completedAt: null,
        };

        this.progress.set(userId, progress);
        logger.info(`Activation path started for user=${userId} tenant=${tenantId}`);
        return progress;
    }

    startStep(userId: string, stepId: ActivationStepId): void {
        const p = this.progress.get(userId);
        if (!p) return;

        p.steps[stepId].status = 'in_progress';
        p.steps[stepId].startedAt = new Date();
    }

    completeStep(userId: string, stepId: ActivationStepId): void {
        const p = this.progress.get(userId);
        if (!p) return;

        const now = new Date();
        const step = p.steps[stepId];
        step.status = 'completed';
        step.completedAt = now;
        step.durationMs = step.startedAt
            ? now.getTime() - step.startedAt.getTime()
            : null;

        // Check for activation moment (first successful send)
        if (stepId === 'send_test_email' && !p.activatedAt) {
            p.activatedAt = now;
            const totalMs = now.getTime() - p.startedAt.getTime();
            logger.info(`User activated — first send completed user=${p.userId} tenant=${p.tenantId} totalMs=${totalMs}`);
        }

        // Check if all required steps are done
        const allRequiredDone = ACTIVATION_STEPS
            .filter(s => s.required)
            .every(s => p.steps[s.id].status === 'completed');

        if (allRequiredDone && !p.completedAt) {
            p.completedAt = now;
            logger.info(`All required activation steps completed user=${p.userId}`);
        }
    }

    skipStep(userId: string, stepId: ActivationStepId): void {
        const p = this.progress.get(userId);
        if (!p) return;
        p.steps[stepId].status = 'skipped';
    }

    getProgress(userId: string): ActivationProgress | null {
        return this.progress.get(userId) ?? null;
    }

    /** Percentage of required steps completed */
    getCompletionPercent(userId: string): number {
        const p = this.progress.get(userId);
        if (!p) return 0;

        const required = ACTIVATION_STEPS.filter(s => s.required);
        const done = required.filter(s => p.steps[s.id].status === 'completed');
        return Math.round((done.length / required.length) * 100);
    }

    /** Current step the user should be working on */
    getCurrentStep(userId: string): ActivationStep | null {
        const p = this.progress.get(userId);
        if (!p) return null;

        for (const step of ACTIVATION_STEPS) {
            if (p.steps[step.id].status === 'not_started' || p.steps[step.id].status === 'in_progress') {
                return step;
            }
        }
        return null; // all done
    }

    /** Time to activation (first send) in milliseconds, or null if not yet activated */
    getTimeToActivation(userId: string): number | null {
        const p = this.progress.get(userId);
        if (!p || !p.activatedAt) return null;
        return p.activatedAt.getTime() - p.startedAt.getTime();
    }

    // ── Aggregate metrics ──

    getActivationStats(): {
        totalUsers: number;
        activatedUsers: number;
        activationRate: number;
        medianTimeToActivationMs: number | null;
        stepCompletionRates: Record<ActivationStepId, number>;
    } {
        const all = Array.from(this.progress.values());
        const activated = all.filter(p => p.activatedAt !== null);
        const activationTimes = activated
            .map(p => p.activatedAt!.getTime() - p.startedAt.getTime())
            .sort((a, b) => a - b);

        const median: number | null = activationTimes.length > 0
            ? activationTimes[Math.floor(activationTimes.length / 2)] ?? null
            : null;

        const stepRates: Record<string, number> = {};
        for (const step of ACTIVATION_STEPS) {
            const completed = all.filter(p => p.steps[step.id].status === 'completed').length;
            stepRates[step.id] = all.length > 0 ? completed / all.length : 0;
        }

        return {
            totalUsers: all.length,
            activatedUsers: activated.length,
            activationRate: all.length > 0 ? activated.length / all.length : 0,
            medianTimeToActivationMs: median,
            stepCompletionRates: stepRates as Record<ActivationStepId, number>,
        };
    }
}

// ────────────────────────────────────────────────────────────────────
// Singleton
// ────────────────────────────────────────────────────────────────────

export const activationTracker = new ActivationTracker();

// ────────────────────────────────────────────────────────────────────
// Sandbox Mode — safe playground for first sends
// ────────────────────────────────────────────────────────────────────

export interface SandboxConfig {
    /** Emails are only delivered to addresses matching this pattern */
    allowedRecipientPattern: RegExp;
    /** Max sends per hour in sandbox mode */
    hourlyRateLimit: number;
    /** Auto-generated test recipients */
    testRecipients: string[];
}

export const SANDBOX_DEFAULTS: SandboxConfig = {
    allowedRecipientPattern: /^.*@(sandbox\.apexmail\.ee|example\.com)$/i,
    hourlyRateLimit: 50,
    testRecipients: [
        'success@sandbox.apexmail.ee',
        'bounce@sandbox.apexmail.ee',
        'complaint@sandbox.apexmail.ee',
        'delay@sandbox.apexmail.ee',
    ],
};

/**
 * Validates that a send request is safe in sandbox mode
 */
export function validateSandboxSend(
    to: string,
    config: SandboxConfig = SANDBOX_DEFAULTS
): { allowed: boolean; reason: string | null } {
    if (!config.allowedRecipientPattern.test(to)) {
        return {
            allowed: false,
            reason: `In sandbox mode, you can only send to addresses matching ${config.allowedRecipientPattern}. Use one of the test addresses: ${config.testRecipients.join(', ')}`,
        };
    }
    return { allowed: true, reason: null };
}
