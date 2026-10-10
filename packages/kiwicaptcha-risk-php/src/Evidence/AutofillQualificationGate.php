<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

/**
 * The runtime autofill-qualification gate (change.md 3.2.2): the decoy
 * escalation may only be armed when the qualification matrix
 * (tests/browser/qualification/autofill-matrix.json) passes every
 * required surface of the registry
 * (tests/browser/qualification/surfaces.json), so a password manager
 * can never trip the escalation on a real user.
 *
 * This class applies the same rules the release validator
 * (tools/ci/validate-autofill-qualification.mjs) enforces: every
 * registry surface with required=true carries exactly one row with
 * status pass, an exact non-placeholder version, and a tested_at inside
 * the qualification window (both decoy controls recorded). The
 * committed matrix is deliberately fail-closed, so the gate is closed
 * out of the box and the escalation is inert until the manual
 * qualification rows land.
 *
 * A missing, malformed or unreadable matrix closes the gate
 * (fail-closed in the user-safe direction: the escalation is an
 * additive price raise, so an unreadable record must never arm it).
 *
 * The matrix alone must not be the only way to open the gate: a
 * runtime security decision cannot depend solely on tests/ QA data.
 * An explicit configuration value (the `armed` flag, see
 * {@see self::fromConfiguration()}) opens the gate as a deliberate
 * operator decision, and a deployment may point the matrix/registry
 * pair at a versioned asset outside tests/ that the doctor validates.
 */
final class AutofillQualificationGate
{
    private const QUALIFICATION_WINDOW_DAYS = 90;

    /** The version placeholders that never record a qualification. */
    private const VERSION_PLACEHOLDER = '/^(current|tbd|tba|unknown|blank|n\/?a|none|null|pending|unversioned|-+)?$/i';

    /** Cached verdict of the current matrix (the gate is asked per hit). */
    private ?bool $verdict = null;

    /**
     * @param bool $explicitlyArmed the explicit configuration value: when
     *                              true the gate is open without consulting
     *                              any matrix (the operator has taken
     *                              responsibility for the autofill surfaces)
     */
    public function __construct(
        private readonly string $matrixPath,
        private readonly string $registryPath,
        private readonly int $windowDays = self::QUALIFICATION_WINDOW_DAYS,
        private readonly bool $explicitlyArmed = false,
    ) {
    }

    /**
     * The gate over the committed matrix paths (repo-root relative),
     * the canonical matrix-driven runtime surface. Fail-closed: the
     * committed matrix carries no passing rows until real qualification
     * lands.
     */
    public static function committed(): self
    {
        return new self(
            dirname(__DIR__, 3) . '/tests/browser/qualification/autofill-matrix.json',
            dirname(__DIR__, 3) . '/tests/browser/qualification/surfaces.json',
        );
    }

    /**
     * The configuration-driven gate (the Symfony wiring surface). An
     * explicit `armed` value opens the gate with no matrix dependency;
     * otherwise the given (or committed) matrix pair decides, fail-closed.
     */
    public static function fromConfiguration(
        bool $explicitlyArmed = false,
        ?string $matrixPath = null,
        ?string $registryPath = null,
        int $windowDays = self::QUALIFICATION_WINDOW_DAYS,
    ): self {
        if ($explicitlyArmed) {
            return new self($matrixPath ?? '', $registryPath ?? '', $windowDays, true);
        }
        $committed = self::committed();

        return new self(
            $matrixPath ?? $committed->matrixPath,
            $registryPath ?? $committed->registryPath,
            $windowDays,
        );
    }

    /** True when the operator explicitly armed the gate by configuration. */
    public function isExplicitlyArmed(): bool
    {
        return $this->explicitlyArmed;
    }

    /**
     * The matrix asset paths this gate reads ('' when explicitly armed
     * with no asset). The doctor validates a configured pair.
     *
     * @return array{0: string, 1: string}
     */
    public function assetPaths(): array
    {
        return [$this->matrixPath, $this->registryPath];
    }

    /**
     * True when the gate is open: the explicit configuration value, or
     * every required surface of the registry qualified.
     */
    public function isOpen(): bool
    {
        if ($this->explicitlyArmed) {
            return true;
        }
        if ($this->verdict === null) {
            $this->verdict = $this->evaluate();
        }

        return $this->verdict;
    }

    private function evaluate(): bool
    {
        $registry = $this->readJson($this->registryPath);
        $matrix = $this->readJson($this->matrixPath);
        if ($registry === null || $matrix === null) {
            return false;
        }
        if (($registry['schema'] ?? null) !== 'kiwicaptcha.autofill-surfaces/1'
            || ($matrix['schema'] ?? null) !== 'kiwicaptcha.autofill-qualification/1') {
            return false;
        }
        $surfaces = $registry['surfaces'] ?? null;
        $rows = $matrix['rows'] ?? null;
        if (!is_array($surfaces) || !is_array($rows)) {
            return false;
        }
        $byId = [];
        foreach ($surfaces as $surface) {
            if (!is_array($surface) || !isset($surface['id'], $surface['required'])) {
                return false;
            }
            $byId[(string) $surface['id']] = $surface;
        }
        $passRows = [];
        foreach ($rows as $row) {
            if (!is_array($row) || !isset($row['surface']) || !is_string($row['surface'])) {
                return false;
            }
            if (($row['status'] ?? null) === 'pass') {
                $passRows[$row['surface']] ??= $row;
            }
        }
        $now = $this->nowMs();
        foreach ($byId as $id => $surface) {
            if ($surface['required'] !== true) {
                continue;
            }
            $row = $passRows[$id] ?? null;
            if ($row === null || !$this->passRowQualifies($row, $now)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The pass-row evidence rule: an exact non-placeholder version, a
     * strict ISO-8601 tested_at inside the window, and both decoy
     * controls recorded as passing with an observation note.
     */
    private function passRowQualifies(array $row, int $nowMs): bool
    {
        $version = $row['version'] ?? null;
        if (!is_string($version) || trim($version) === '' || preg_match(self::VERSION_PLACEHOLDER, trim($version)) === 1) {
            return false;
        }
        $testedAt = $row['tested_at'] ?? null;
        if (!is_string($testedAt) || trim($testedAt) === '') {
            return false;
        }
        $testedMs = $this->parseIsoMs($testedAt);
        if ($testedMs === null) {
            return false;
        }
        $windowMs = $this->windowDays * 86400000;
        if ($nowMs - $testedMs > $windowMs || $testedMs - $nowMs > 300000) {
            return false;
        }
        $controls = $row['controls'] ?? null;
        if (!is_array($controls)) {
            return false;
        }
        foreach (['negative', 'positive'] as $name) {
            $control = $controls[$name] ?? null;
            if (!is_array($control)
                || ($control['result'] ?? null) !== 'pass'
                || !isset($control['note'])
                || !is_string($control['note'])
                || trim($control['note']) === '') {
                return false;
            }
        }

        return true;
    }

    private function readJson(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $raw = file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        try {
            $decoded = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Strict ISO-8601 date or offset-carrying date-time to epoch ms
     * (real calendar components, no local-time fallback: a timestamp
     * with a time-of-day but without a UTC designator or numeric offset
     * is rejected, like the validator's rule).
     */
    private function parseIsoMs(string $value): ?int
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2}([Tt]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|z|[+-]\d{2}:?\d{2}))?$/', $value)) {
            return null;
        }
        $hasTime = preg_match('/[Tt]\d{2}:\d{2}/', $value) === 1;
        $hasZone = preg_match('/(Z|z|[+-]\d{2}:?\d{2})$/', $value) === 1;
        if ($hasTime && !$hasZone) {
            return null;
        }
        try {
            $parsed = new \DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
        $errors = \DateTimeImmutable::getLastErrors();
        if (is_array($errors) && (($errors['warning_count'] ?? 0) > 0 || ($errors['error_count'] ?? 0) > 0)) {
            return null;
        }

        return (int) $parsed->format('Uv');
    }

    protected function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }
}
