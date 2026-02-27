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

  if (typeof window !== 'undefined') {
    if (window[guardKey]) return;
    window[guardKey] = true;
  } else {
    if (globalThis.__apexmail_console_guard_installed__) return;
    globalThis.__apexmail_console_guard_installed__ = true;
  }

  const noop = (): void => {};
  console.warn = noop;
  console.error = noop;
}

installConsoleGuard();

export {};