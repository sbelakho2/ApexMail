import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const settingsPath = join(currentDir, '../../../web/src/app/(dashboard)/settings/page.tsx');
const settingsSource = readFileSync(settingsPath, 'utf-8');

describe('Settings fallback and timeout safeguards', () => {
  it('includes read-only fallback behavior when profile APIs fail', () => {
    expect(settingsSource).toContain('setReadOnlyMode(true)');
    expect(settingsSource).toContain('readOnlyMode');
  });

  it('cleans up save/reset timeout references on unmount', () => {
    expect(settingsSource).toContain('if (saveTimerRef.current) clearTimeout(saveTimerRef.current)');
    expect(settingsSource).toContain('if (resetTimerRef.current) clearTimeout(resetTimerRef.current)');
  });

  it('keeps unsaved-change unload guard in place', () => {
    expect(settingsSource).toContain("window.addEventListener('beforeunload', handleBeforeUnload)");
  });
});
