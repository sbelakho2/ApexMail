import { Buffer } from 'node:buffer';
import { Script, createContext } from 'node:vm';
import { parentPort, workerData } from 'node:worker_threads';
import { render } from '@react-email/render';
import { convert } from 'html-to-text';
import * as React from 'react';
import * as ReactEmailComponents from '@react-email/components';
import * as ReactJsxRuntime from 'react/jsx-runtime';

interface WorkerPayload {
  transpiledCode: string;
  props: Record<string, unknown>;
  pretty: boolean;
  timeoutMs: number;
  maxRenderedBytes: number;
}

interface WorkerResponse {
  ok: boolean;
  value?: { html: string; text: string };
  error?: { message: string; code?: string };
}

class WorkerRenderError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.code = code;
  }
}

const payload = workerData as WorkerPayload;

const ALLOWED_MODULES: Record<string, unknown> = {
  react: React,
  'react/jsx-runtime': ReactJsxRuntime,
  '@react-email/components': ReactEmailComponents,
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

function postMessage(message: WorkerResponse): void {
  parentPort?.postMessage(message);
  parentPort?.close();
}

async function renderTemplate(): Promise<{ html: string; text: string }> {
  const sandbox = Object.create(null) as Record<string, unknown>;
  const module = { exports: {} as Record<string, unknown> };

  sandbox.module = module;
  sandbox.exports = module.exports;
  sandbox.require = (moduleName: string): unknown => {
    if (moduleName in ALLOWED_MODULES) {
      return ALLOWED_MODULES[moduleName];
    }
    throw new WorkerRenderError(
      `Module "${moduleName}" is not allowed in email templates.`,
      'MODULE_NOT_ALLOWED',
    );
  };
  sandbox.process = { env: { NODE_ENV: 'production' } };
  sandbox.console = {
    log: () => undefined,
    warn: () => undefined,
    error: () => undefined,
  };
  sandbox.global = sandbox;
  sandbox.globalThis = sandbox;

  const context = createContext(sandbox, {
    codeGeneration: { strings: false, wasm: false },
  });
  const script = new Script(payload.transpiledCode, {
    filename: 'react-email-template.js',
  });
  script.runInContext(context, { timeout: payload.timeoutMs });

  const componentModule = module.exports as { default?: unknown };
  const Component = componentModule?.default;
  if (typeof Component !== 'function') {
    throw new WorkerRenderError(
      'React Email template must have a default export that is a React component function.',
      'NO_DEFAULT_EXPORT',
    );
  }

  const element = React.createElement(Component, payload.props ?? {});
  const html = await render(element, { pretty: payload.pretty });
  if (Buffer.byteLength(html, 'utf8') > payload.maxRenderedBytes) {
    throw new WorkerRenderError(
      'Rendered output exceeds the maximum allowed size.',
      'RENDER_OUTPUT_TOO_LARGE',
    );
  }

  const text = convert(html, {
    wordwrap: false,
    selectors: [
      { selector: 'img', format: 'skip' },
      { selector: 'a', options: { hideLinkHrefIfSameAsText: true } },
    ],
  }).trim();

  return { html, text };
}

void (async () => {
  try {
    const result = await renderTemplate();
    postMessage({ ok: true, value: result });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const code = err instanceof WorkerRenderError ? err.code : 'RENDER_ERROR';
    postMessage({ ok: false, error: { message, code } });
  }
})();
