const guardKey = '__apexmail_console_guard_installed__';

declare global {
  interface Window {
    [guardKey]?: boolean;
  }

  interface GlobalThis {
    __apexmail_console_guard_installed__?: boolean;
  }
}

function installConsoleGuard(): void {
  if (process.env.NODE_ENV !== 'production') {
    return;
  }

  // Detect server-side context — preserve console.error/warn on the server
  // so that security logging, audit events, and error tracking continue to work.
  const isServer = typeof window === 'undefined';

  if (typeof window !== 'undefined') {
    if (window[guardKey]) return;
    window[guardKey] = true;
  } else {
    if ((globalThis as Record<string, unknown>).__apexmail_console_guard_installed__) return;
    (globalThis as Record<string, unknown>).__apexmail_console_guard_installed__ = true;
  }

  const noop = (): void => {};
  console.log = noop;
  console.info = noop;

  // Only suppress warn/error on the client (browser). Server-side security
  // logging must continue to function in production.
  if (!isServer) {
    console.warn = noop;
    console.error = noop;
  }
}

installConsoleGuard();

export {};