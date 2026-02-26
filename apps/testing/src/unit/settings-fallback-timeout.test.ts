import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const settingsPagePath = join(currentDir, '../../../web/src/app/(dashboard)/settings/page.tsx');
const settingsControllerPath = join(currentDir, '../../../web/src/app/(dashboard)/settings/use-settings-controller.ts');
const settingsPageSource = readFileSync(settingsPagePath, 'utf-8');
const settingsControllerSource = readFileSync(settingsControllerPath, 'utf-8');

describe('Settings fallback and timeout safeguards', () => {
  it('includes read-only fallback behavior when profile APIs fail', () => {
    expect(settingsControllerSource).toContain('setReadOnlyMode(true)');
    expect(settingsControllerSource).toContain('readOnlyMode');
  });

  it('cleans up save/reset timeout references on unmount', () => {
    expect(settingsControllerSource).toContain('if (saveTimerRef.current) clearTimeout(saveTimerRef.current)');
    expect(settingsControllerSource).toContain('if (resetTimerRef.current) clearTimeout(resetTimerRef.current)');
  });

  it('keeps unsaved-change unload guard in place', () => {
    expect(settingsPageSource).toContain("window.addEventListener('beforeunload', handleBeforeUnload)");
  });
});
