<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Evidence;

/**
 * The Redis-backed decoy-escalation record (the write/read path of the
 * canonical decoy_escalation.lua script).
 *
 * This class owns its Redis scripting surface through the tiny runner
 * contract below; it never touches the risk state store internals (the
 * observation wire and the store adapters stay frozen). The runner is
 * the single seam a deployment adapts to its client (phpredis,
 * Predis, a sidecar), mirroring how the store packages own their
 * connections.
 */
final class DecoyEscalationStore implements DecoyEscalationReaderInterface
{
    /**
     * The canonical script, loaded from this package's resources copy
     * (byte-identical with protocol/risk-v1/ and the Rust resources
     * copy; the fixture test asserts the parity).
     */
    public const SCRIPT_PATH = __DIR__ . '/../../resources/decoy_escalation.lua';

    /**
     * The canonical script text, loaded once from the resources copy.
     * A missing copy fails loudly (the parity fixture would fail too).
     */
    public static function script(): string
    {
        static $script = null;
        if ($script === null) {
            $raw = @file_get_contents(self::SCRIPT_PATH);
            if ($raw === false) {
                throw new \RuntimeException('Cannot locate the bundled decoy-escalation script at resources/decoy_escalation.lua');
            }
            $script = $raw;
        }

        return $script;
    }

    public function __construct(
        private readonly RedisScriptRunnerInterface $runner,
        private readonly AutofillQualificationGate $gate,
        private readonly string $namespace,
        private readonly int $ttlMs = DecoyEscalation::ESCALATION_TTL_MS,
    ) {
        if ($this->ttlMs < 1) {
            throw new \InvalidArgumentException('the decoy escalation TTL must be at least one millisecond');
        }
        if ($this->namespace === '' || preg_match('/[{}:]/', $this->namespace) === 1) {
            throw new \InvalidArgumentException('the decoy escalation namespace must be a safe key component');
        }
    }

    /**
     * Records one server-confirmed decoy hit for the session. The
     * autofill-qualification gate is evaluated per call and passed to
     * the script: a closed gate makes the script refuse the write, so a
     * password manager can never arm the escalation. Returns the
     * record's hit count (0 when the gate closed the write).
     */
    public function recordConfirmedHit(string $session, ?int $nowMs = null): int
    {
        if ($session === '' || preg_match('/[{}:]/', $session) === 1) {
            throw new \InvalidArgumentException('the session identifier must be a safe key component');
        }
        $now = $nowMs ?? (int) floor(microtime(true) * 1000);
        $result = $this->runner->evalScript(
            self::script(),
            [$this->key($session)],
            ['record', '1', $this->gate->isOpen() ? '1' : '0', (string) $now, (string) $this->ttlMs],
        );

        return is_int($result) ? $result : 0;
    }

    /**
     * The reader seam: true when the session carries a live escalation
     * record (inside its window). Any backend failure degrades to
     * not-live, never to an escalation.
     */
    public function escalationLive(?string $session): bool
    {
        if ($session === null || $session === '' || preg_match('/[{}:]/', $session) === 1) {
            return false;
        }
        try {
            $result = $this->runner->evalScript(
                self::script(),
                [$this->key($session)],
                ['read', '0', '0', (string) (int) floor(microtime(true) * 1000), (string) $this->ttlMs],
            );
        } catch (\Throwable) {
            return false;
        }

        return $result === 1 || $result === true;
    }

    private function key(string $session): string
    {
        return 'decoy_esc:' . $this->namespace . ':' . $session;
    }
}
