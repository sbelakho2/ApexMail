import { describe, expect, it, vi } from 'vitest';

describe('Fix 18: createEmailValidator exposes lifecycle cleanup and registers process-exit cleanup', () => {
  it('registers process-exit cleanup hooks for created validators', async () => {
    vi.resetModules();
    const onceSpy = vi.spyOn(process, 'once');

    const { createEmailValidator } = await import('../validation/index.js');
    const validator = createEmailValidator({ checkMx: false });

    expect(typeof validator.destroy).toBe('function');
    const registeredBeforeExit = onceSpy.mock.calls.some(([eventName]) => eventName === 'beforeExit');
    expect(registeredBeforeExit).toBe(true);

    validator.destroy();
    onceSpy.mockRestore();
  });
});
