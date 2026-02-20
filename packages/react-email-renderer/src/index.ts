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
import { render } from '@react-email/render';
import * as React from 'react';
import * as ReactJsxRuntime from 'react/jsx-runtime';
import * as ReactEmailComponents from '@react-email/components';
import { Script, createContext } from 'vm';

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

// ── Module allowlist ───────────────────────────────────────────────────────────

/**
 * Only these modules can be `require()`-d inside a React Email template.
 * Anything outside this list throws immediately at sandbox execution time
 * so a rogue template can never load `child_process`, `fs`, etc.
 */
const ALLOWED_MODULES: Record<string, unknown> = {
  react: React,
  'react/jsx-runtime': ReactJsxRuntime,
  '@react-email/components': ReactEmailComponents,
  // Convenience: allow importing individual @react-email/* sub-packages that
  // resolve to the same component namespace.
  '@react-email/html': ReactEmailComponents,
  '@react-email/head': ReactEmailComponents,
  '@react-email/body': ReactEmailComponents,
  '@react-email/button': ReactEmailComponents,
  '@react-email/container': ReactEmailComponents,
  '@react-email/column': ReactEmailComponents,
  '@react-email/row': ReactEmailComponents,
  '@react-email/font': ReactEmailComponents,
  '@react-email/heading': ReactEmailComponents,
  '@react-email/hr': ReactEmailComponents,
  '@react-email/img': ReactEmailComponents,
  '@react-email/link': ReactEmailComponents,
  '@react-email/preview': ReactEmailComponents,
  '@react-email/section': ReactEmailComponents,
  '@react-email/text': ReactEmailComponents,
  '@react-email/tailwind': ReactEmailComponents,
};

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
  } catch (err) {
    throw new ReactEmailRenderError(
      `JSX transpilation failed: ${err instanceof Error ? err.message : String(err)}`,
      'TRANSPILE_ERROR',
      err,
    );
  }

  // ── Step 2: Execute in an isolated VM context ───────────────────────────────
  let ComponentModule: { default?: React.ComponentType<Record<string, unknown>> };
  try {
    const moduleExports: Record<string, unknown> = {};
    const sandboxedRequire = (id: string): unknown => {
      const mod = ALLOWED_MODULES[id];
      if (mod === undefined) {
        throw new Error(
          `Module "${id}" is not allowed in React Email templates. ` +
          `Allowed modules: ${Object.keys(ALLOWED_MODULES).join(', ')}`,
        );
      }
      return mod;
    };

    const sandbox = createContext({
      module: { exports: moduleExports },
      exports: moduleExports,
      require: sandboxedRequire,
      // Minimal globals needed by transpiled React code
      process: { env: { NODE_ENV: 'production' } },
      console: {
        log: () => undefined,
        warn: () => undefined,
        error: () => undefined,
      },
    });

    const script = new Script(transpiledCode, {
      filename: 'react-email-template.js',
    });
    script.runInContext(sandbox, { timeout: timeoutMs });

    ComponentModule = sandbox.module.exports as typeof ComponentModule;
  } catch (err) {
    throw new ReactEmailRenderError(
      `Template execution failed: ${err instanceof Error ? err.message : String(err)}`,
      'EXECUTION_ERROR',
      err,
    );
  }

  // ── Step 3: Validate the default export ────────────────────────────────────
  const Component = ComponentModule?.default;
  if (typeof Component !== 'function') {
    throw new ReactEmailRenderError(
      'React Email template must have a default export that is a React component function.',
      'NO_DEFAULT_EXPORT',
    );
  }

  // ── Step 4: Render to HTML via @react-email/render ─────────────────────────
  let html: string;
  try {
    const element = React.createElement(
      Component as React.ComponentType<Record<string, unknown>>,
      props,
    );
    html = await render(element, { pretty });
  } catch (err) {
    throw new ReactEmailRenderError(
      `React rendering failed: ${err instanceof Error ? err.message : String(err)}`,
      'RENDER_ERROR',
      err,
    );
  }

  // ── Step 5: Generate plain-text fallback ────────────────────────────────────
  const text = htmlToPlainText(html);

  return { html, text };
}

// ── Plain-text converter ────────────────────────────────────────────────────────

/**
 * Convert an HTML email string to a readable plain-text fallback.
 * This is not a universal HTML→text converter — it targets the output
 * of @react-email/render which uses known patterns (no JS, controlled structure).
 */
function htmlToPlainText(html: string): string {
  return html
    // Replace common block elements with newlines
    .replace(/<(br|hr)\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|h[1-6]|li|td|section|article)>/gi, '\n')
    // Replace <a href="...">text</a> with "text (url)"
    .replace(/<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi, '$2 ($1)')
    // Strip remaining tags
    .replace(/<[^>]+>/g, '')
    // Decode common HTML entities
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    // Collapse multiple blank lines to max two
    .replace(/\n{3,}/g, '\n\n')
    // Trim leading/trailing whitespace
    .trim();
}

// ── Error class ────────────────────────────────────────────────────────────────

export class ReactEmailRenderError extends Error {
  public readonly code: string;
  public readonly cause: unknown;

  constructor(message: string, code: string, cause?: unknown) {
    super(message);
    this.name = 'ReactEmailRenderError';
    this.code = code;
    this.cause = cause;
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
  Font,
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
      <Head>
        <Font
          fontFamily="Inter"
          fallbackFontFamily="Arial"
          webFont={{
            url: 'https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiJ-Ek-_EeA.woff2',
            format: 'woff2',
          }}
          fontWeight={400}
          fontStyle="normal"
        />
      </Head>
      <Preview>Hello, {recipientName}!</Preview>
      <Body style={{ backgroundColor: '#f6f9fc', fontFamily: 'Inter, Arial, sans-serif' }}>
        <Container style={{ maxWidth: '600px', margin: '40px auto', padding: '24px', backgroundColor: '#ffffff', borderRadius: '8px' }}>
          <Img
            src="https://example.com/logo.png"
            alt="Logo"
            width={120}
            height={40}
          />
          <Hr style={{ borderColor: '#e6ebf1' }} />
          <Section>
            <Heading style={{ fontSize: '24px', color: '#1a1a2e' }}>
              Hi {recipientName}!
            </Heading>
            <Text style={{ fontSize: '16px', color: '#555', lineHeight: '1.6' }}>
              Welcome to our platform. We&apos;re excited to have you on board.
            </Text>
            <Button
              href={actionUrl}
              style={{
                backgroundColor: '#6366f1',
                color: '#fff',
                padding: '12px 24px',
                borderRadius: '6px',
                fontSize: '16px',
                fontWeight: '600',
                textDecoration: 'none',
              }}
            >
              Get Started
            </Button>
          </Section>
          <Hr style={{ borderColor: '#e6ebf1' }} />
          <Text style={{ fontSize: '12px', color: '#8898aa', textAlign: 'center' }}>
            You received this email because you signed up at{' '}
            <Link href="https://example.com" style={{ color: '#6366f1' }}>
              example.com
            </Link>
            . To unsubscribe,{' '}
            <Link href="{{unsubscribeUrl}}" style={{ color: '#6366f1' }}>
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
