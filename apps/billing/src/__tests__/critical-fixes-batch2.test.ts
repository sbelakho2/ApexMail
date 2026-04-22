import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 2 tests: Fixes 6-10 (Security + compile fixes)
// ──────────────────────────────────────────────────────────────────────────────

// ── Fix 6: SMTP command injection prevention ─────────────────────────────────
// Before fix: MAIL FROM and RCPT TO commands used unsanitized user input,
// allowing CRLF injection to execute arbitrary SMTP commands.

describe('Fix 6: SMTP command injection prevention', () => {
  const smtpSource = readFileSync(
    resolve(__dirname, '../../../../services/mail-server/crates/outbound-queue/src/smtp_sender.rs'),
    'utf-8'
  );

  it('MAIL FROM uses sanitized address', () => {
    // The format string for MAIL FROM must use a sanitized variable
    expect(smtpSource).toContain('sanitize_smtp_address');
    expect(smtpSource).toMatch(/sanitized_from\s*=.*sanitize_smtp_address\(from\)/);
    expect(smtpSource).toContain('MAIL FROM:<{}>');
  });

  it('RCPT TO uses sanitized address', () => {
    expect(smtpSource).toMatch(/sanitized_rcpt\s*=.*sanitize_smtp_address\(recipient\)/);
  });

  it('sanitize_smtp_address strips dangerous characters', () => {
    // Must strip CR, LF, NUL, angle brackets, and spaces
    expect(smtpSource).toMatch(/fn sanitize_smtp_address/);
    const fnMatch = smtpSource.match(/fn sanitize_smtp_address[\s\S]*?\n\s*\}/);
    expect(fnMatch).not.toBeNull();
    const fnBody = fnMatch![0];
    expect(fnBody).toContain("'\\r'");
    expect(fnBody).toContain("'\\n'");
    expect(fnBody).toContain("'\\0'");
    expect(fnBody).toContain("'<'");
    expect(fnBody).toContain("'>'");
  });
});

// ── Fix 7: Timing attack on service token comparison ─────────────────────────
// Before fix: used == for token comparison which short-circuits on first
// differing byte, leaking token length and content via timing.

describe('Fix 7: Constant-time token comparison', () => {
  const authSource = readFileSync(
    resolve(__dirname, '../../../../services/mail-server/crates/mail-common/src/internal_auth.rs'),
    'utf-8'
  );

  it('uses subtle::ConstantTimeEq for token comparison', () => {
    expect(authSource).toContain('use subtle::ConstantTimeEq');
    expect(authSource).toContain('ct_eq');
  });

  it('does NOT use direct == comparison for tokens', () => {
    // The old vulnerable pattern must not exist
    expect(authSource).not.toMatch(/provided\.as_deref\(\)\s*==\s*Some\(expected\)/);
  });

  it('subtle is in Cargo.toml dependencies', () => {
    const cargoToml = readFileSync(
      resolve(__dirname, '../../../../services/mail-server/crates/mail-common/Cargo.toml'),
      'utf-8'
    );
    expect(cargoToml).toContain('subtle');
  });
});

// ── Fix 8: No hardcoded secrets in VCS ───────────────────────────────────────
// Before fix: services/mail-server/secrets/postgres_password contained
// 'apexmail-test-password' in plaintext.

describe('Fix 8: No hardcoded secrets', () => {
  it('postgres_password does not contain the old test password', () => {
    const secretFile = readFileSync(
      resolve(__dirname, '../../../../services/mail-server/secrets/postgres_password'),
      'utf-8'
    );
    expect(secretFile).not.toContain('apexmail-test-password');
  });

  it('secrets directory is in .gitignore', () => {
    const gitignore = readFileSync(
      resolve(__dirname, '../../../../.gitignore'),
      'utf-8'
    );
    expect(gitignore).toContain('**/secrets/');
  });
});

// ── Fix 9: bot-detector-native BUILTIN_PATTERNS type mismatch ────────────────
// Before fix: BUILTIN_PATTERNS declared as &[(&str, &str, &str)] but
// initialized with PatternEntry struct literals — won't compile.

describe('Fix 9: bot-detector-native compiles', () => {
  const botSource = readFileSync(
    resolve(__dirname, '../../../../packages/bot-detector-native/src/lib.rs'),
    'utf-8'
  );

  it('BUILTIN_PATTERNS type matches initialization', () => {
    // Type declaration must match tuple syntax
    expect(botSource).toMatch(/BUILTIN_PATTERNS:\s*&\[\(&str,\s*&str,\s*&str\)\]/);
    // Extract the BUILTIN_PATTERNS array block
    const arrayMatch = botSource.match(/BUILTIN_PATTERNS:\s*&\[[\s\S]*?\];\s*$/m);
    expect(arrayMatch).not.toBeNull();
    // Within the array, initialization must use tuples (parentheses), not struct literals
    expect(arrayMatch![0]).toContain('("googlebot"');
    expect(arrayMatch![0]).not.toContain('PatternEntry {');
  });

  it('load_builtin_patterns converts tuples to PatternEntry', () => {
    // The conversion function should destructure tuples
    expect(botSource).toMatch(/\.map\(\|\(pattern, category, label\)\|/);
  });
});

// ── Fix 10: validator-native RESOLVER initialized ────────────────────────────
// Before fix: RESOLVER OnceLock was never set() — only get() was called,
// so DNS lookups always returned "resolver not initialized".

describe('Fix 10: validator-native RESOLVER initialization', () => {
  const validatorSource = readFileSync(
    resolve(__dirname, '../../../../packages/validator-native/src/lib.rs'),
    'utf-8'
  );

  it('get_resolver uses get_or_init instead of just get', () => {
    expect(validatorSource).toContain('get_or_init');
    // Old pattern must be gone
    expect(validatorSource).not.toMatch(/fn get_resolver\(\).*Option/);
  });

  it('callers do not use Option pattern matching for resolver', () => {
    // The old "let Some(resolver) = get_resolver() else" must be gone
    expect(validatorSource).not.toContain('Some(resolver) = get_resolver()');
  });
});
