/**
 * @apexmail/react-email-renderer
 *
 * Server-side renderer for React Email JSX templates stored as source strings.
 *
 * How it works:
 *  1. Template source (JSX/TSX) is stored in the database as a plain string.
 *  2. At render time, esbuild transpiles the JSX → CommonJS JS entirely in
 *     memory (no disk writes, no temp files).
 *  3. A sandboxed module context is created via Node's `vm` module with only
 *     `react` and `@react-email/components` injected — no arbitrary require().
 *  4. The default export (the React component) is rendered to HTML via
 *     `@react-email/render`, which internally uses ReactDOM/server.
 *  5. A plain-text fallback is auto-generated from the HTML when not provided.
 *
 * Security model:
 *  - No filesystem access from within the sandbox.
 *  - Only a fixed allowlist of modules can be required.
 *  - Templates run in their own V8 context isolated from the main process.
 *  - esbuild target is node18 — no eval of untrusted native code.
 *  - Execution timeout is enforced at the VM level (5 s default).
 *
 * Usage:
 *  ```ts
 *  import { renderReactEmailTemplate } from '@apexmail/react-email-renderer';
 *
 *  const html = await renderReactEmailTemplate(jsxSource, { name: 'Alice' });
 *  ```
 */

import { transform } from 'esbuild';
import { createHash } from 'node:crypto';
import { Worker } from 'node:worker_threads';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface RenderOptions {
  /** Props passed to the root React Email component */
  props?: Record<string, unknown>;
  /** Rendering pretty-print (useful for debugging templates in preview mode) */
  pretty?: boolean;
  /** Maximum VM execution time in milliseconds (default: 5000) */
  timeoutMs?: number;
}

export interface RenderResult {
  /** Full HTML string with inline styles, DOCTYPE, etc. */
  html: string;
  /** Auto-generated plain-text fallback */
  text: string;
}


const MAX_TEMPLATE_BYTES = 1024 * 1024;
const MAX_RENDERED_BYTES = 5 * 1024 * 1024;
const MAX_WORKER_OLD_SPACE_MB = 128;
const TRANSPILE_CACHE_MAX = 200;
const transpileCache = new Map<string, string>();

function getCachedTranspiled(source: string): string | null {
  const key = createHash('sha256').update(source).digest('hex');
  const cached = transpileCache.get(key);
  if (cached) {
    transpileCache.delete(key);
    transpileCache.set(key, cached);
    return cached;
  }
  return null;
}

function setCachedTranspiled(source: string, code: string): void {
  const key = createHash('sha256').update(source).digest('hex');
  transpileCache.set(key, code);
  if (transpileCache.size > TRANSPILE_CACHE_MAX) {
    const oldestEntry = transpileCache.keys().next();
    if (!oldestEntry.done) {
      transpileCache.delete(oldestEntry.value);
    }
  }
}

async function renderInWorker(payload: {
  transpiledCode: string;
  props: Record<string, unknown>;
  pretty: boolean;
  timeoutMs: number;
}): Promise<RenderResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./worker.js', import.meta.url), {
      type: 'module',
      workerData: {
        ...payload,
        maxRenderedBytes: MAX_RENDERED_BYTES,
      },
      resourceLimits: {
        maxOldGenerationSizeMb: MAX_WORKER_OLD_SPACE_MB,
      },
    });

    const timeout = setTimeout(() => {
      worker.terminate().catch(() => undefined);
      reject(new ReactEmailRenderError('Template rendering timed out', 'RENDER_TIMEOUT'));
    }, payload.timeoutMs + 1000);

    worker.once('message', (message: { ok: boolean; value?: RenderResult; error?: { message: string; code?: string } }) => {
      clearTimeout(timeout);
      if (message.ok && message.value) {
        resolve(message.value);
      } else {
        const err = message.error;
        reject(new ReactEmailRenderError(err?.message ?? 'Template rendering failed', err?.code ?? 'RENDER_ERROR'));
      }
    });

    worker.once('error', (err) => {
      clearTimeout(timeout);
      reject(new ReactEmailRenderError(`Worker error: ${err.message}`, 'WORKER_ERROR', err));
    });

    worker.once('exit', (code) => {
      if (code !== 0) {
        clearTimeout(timeout);
        reject(new ReactEmailRenderError(`Worker exited with code ${code}`, 'WORKER_EXIT'));
      }
    });
  });
}

// ── Core renderer ──────────────────────────────────────────────────────────────

/**
 * Render a React Email JSX template source string to HTML + plain text.
 *
 * @param jsxSource - Raw JSX/TSX source of the email template. Must have a
 *   default export that is a React component accepting `props`.
 * @param options   - Render options (props, pretty, timeoutMs)
 * @returns         - `{ html, text }`
 *
 * @throws `ReactEmailRenderError` if transpilation or rendering fails.
 */
export async function renderReactEmailTemplate(
  jsxSource: string,
  options: RenderOptions = {},
): Promise<RenderResult> {
  const { props = {}, pretty = false, timeoutMs = 5000 } = options;

  // ── Step 1: Transpile JSX → CommonJS (in-memory, no disk I/O) ──────────────
  let transpiledCode: string;
  try {
    const cached = getCachedTranspiled(jsxSource);
    if (cached) {
      transpiledCode = cached;
    } else {
      const result = await transform(jsxSource, {
        loader: 'tsx',
        format: 'cjs',
        target: 'node18',
        jsx: 'automatic',
        jsxImportSource: 'react',
        // Strip TypeScript type annotations
        tsconfigRaw: { compilerOptions: { jsx: 'react-jsx' } },
        // Minify whitespace only to keep source maps reasonable
        minifyWhitespace: false,
        logLevel: 'silent',
      });
      transpiledCode = result.code;
      setCachedTranspiled(jsxSource, transpiledCode);
    }
    if (Buffer.byteLength(transpiledCode, 'utf8') > MAX_TEMPLATE_BYTES) {
      throw new ReactEmailRenderError(
        'Template size exceeds the maximum allowed size.',
        'TEMPLATE_TOO_LARGE',
      );
    }
  } catch (err) {
    throw new ReactEmailRenderError(
      `JSX transpilation failed: ${err instanceof Error ? err.message : String(err)}`,
      'TRANSPILE_ERROR',
      err,
    );
  }

  // ── Step 2: Execute + render in a constrained worker ───────────────────────
  return renderInWorker({
    transpiledCode,
    props,
    pretty,
    timeoutMs,
  });
}

// ── Error class ────────────────────────────────────────────────────────────────

export class ReactEmailRenderError extends Error {
  public readonly code: string;

  constructor(message: string, code: string, cause?: unknown) {
    super(message, cause ? { cause } : undefined);
    this.name = 'ReactEmailRenderError';
    this.code = code;
  }
}

// ── Template validation (syntactic pre-check) ──────────────────────────────────

/**
 * Validate that a JSX source string is syntactically correct without
 * executing it. Useful for template creation/update endpoints to give
 * authors immediate feedback before saving to the database.
 *
 * @returns `{ valid: true }` or `{ valid: false, error: string }`
 */
export async function validateReactEmailSource(
  jsxSource: string,
): Promise<{ valid: true } | { valid: false; error: string }> {
  try {
    await transform(jsxSource, {
      loader: 'tsx',
      format: 'cjs',
      target: 'node18',
      jsx: 'automatic',
      jsxImportSource: 'react',
      logLevel: 'silent',
    });
    return { valid: true };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ── Example template generator ─────────────────────────────────────────────────

/**
 * Returns a starter React Email template source with the most common
 * @react-email/components already imported. Useful for the template editor
 * "New template → React Email" flow.
 */
export function getStarterTemplate(componentName = 'EmailTemplate'): string {
  return `import {
  Html,
  Head,
  Body,
  Container,
  Section,
  Heading,
  Text,
  Button,
  Img,
  Link,
  Preview,
  Hr,
} from '@react-email/components';
import * as React from 'react';

interface ${componentName}Props {
  // Define your template variables here
  recipientName?: string;
  actionUrl?: string;
}

export default function ${componentName}({
  recipientName = 'there',
  actionUrl = 'https://example.com',
}: ${componentName}Props) {
  return (
    <Html lang="en">
      <Head />
      <Preview>Hello, {recipientName}!</Preview>
      <Body className="bg-slate-50 font-sans">
        <Container className="mx-auto my-10 max-w-[600px] rounded-lg bg-white p-6">
          <Img
            src="https://example.com/logo.png"
            alt="Logo"
            width={120}
            height={40}
          />
          <Hr className="border-slate-200" />
          <Section>
            <Heading className="text-2xl text-slate-900">
              Hi {recipientName}!
            </Heading>
            <Text className="text-base leading-7 text-slate-600">
              Welcome to our platform. We&apos;re excited to have you on board.
            </Text>
            <Button
              href={actionUrl}
              className="rounded-md bg-indigo-500 px-6 py-3 text-base font-semibold text-white no-underline"
            >
              Get Started
            </Button>
          </Section>
          <Hr className="border-slate-200" />
          <Text className="text-center text-xs text-slate-400">
            You received this email because you signed up at{' '}
            <Link href="https://example.com" className="text-indigo-500">
              example.com
            </Link>
            . To unsubscribe,{' '}
            <Link href="{{unsubscribeUrl}}" className="text-indigo-500">
              click here
            </Link>
            .
          </Text>
        </Container>
      </Body>
    </Html>
  );
}
`;
}
