<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\ArrayChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use KiwiCaptcha\Risk\RiskAction;
use PHPUnit\Framework\TestCase;

/**
 * The ticket() convenience API's SIGNED-EXPIRY INVARIANT: the ticket is
 * ALWAYS signed from the server-held requirement's ACTUAL expiry
 * ($requirement->expiresAt), never the caller-requested $expiresAt. On
 * the FRESH path (no open chain) the requested expiry seeds the chain
 * creation, so a new chain's requirement expiry equals the requested
 * expiry; on the EXISTING path (an open chain of the same transaction)
 * the requirement keeps its ORIGINAL expiry — the signed ticket can
 * never outlive the chain state, and repeated ticket() calls against the
 * same obligation return BYTE-IDENTICAL tickets regardless of the
 * requested expiry (the state store retains the ORIGINAL expiry, so the
 * re-signed ticket must reproduce it exactly).
 */
final class ChainedTicketDeterminismTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** A Kiwi-shaped challenge nonce (base64 of 32 random bytes). */
    private function nonce(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * A service + store on a PINNED clock (the determinism the test
     * asserts is about the signed expiry, so the wall clock must not move
     * between calls).
     */
    private function pinnedService(int $clock): array
    {
        $store = new ArrayChainedChallengeStateStore(static fn (): float => (float) $clock);
        $service = new ChainedChallengeTicketService(
            $store,
            self::SECRET,
            300,
            15,
            now: static fn (): int => $clock,
        );

        return ['store' => $store, 'service' => $service];
    }

    public function testFreshPathSignsTheRequestedExpiry(): void
    {
        $clock = 1000;
        ['service' => $service] = $this->pinnedService($clock);
        $requested = $clock + 300;

        $ticket = $service->ticket($this->nonce(), 'login', '', 1, RiskAction::Argon32, $requested);
        self::assertIsString($ticket);
        $payload = $service->verify($ticket);
        self::assertIsArray($payload);
        self::assertSame($requested, (int) $payload['expiresAt'], 'on the FRESH path the signed expiry equals the requested expiry that seeded the chain');
        $requirement = $service->requirementFor((string) $payload['chainId']);
        self::assertNotNull($requirement);
        self::assertSame($requested, $requirement->expiresAt, 'the fresh chain\'s requirement carries the requested expiry');
    }

    public function testRepeatedCallsAgainstTheSameObligationSignTheOriginalExpiryByteIdentically(): void
    {
        $clock = 1000;
        ['store' => $store, 'service' => $service] = $this->pinnedService($clock);
        $expiryX = $clock + 300;

        $first = $service->ticket($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiryX);
        self::assertIsString($first);
        $payload1 = $service->verify($first);
        self::assertIsArray($payload1);
        self::assertSame($expiryX, (int) $payload1['expiresAt'], 'the first call signs the requested expiry (the fresh path)');

        // The SAME obligation with a LATER requested expiry: the chain
        // already exists with its ORIGINAL expiry — the convenience API
        // must sign the requirement's ACTUAL expiry, so the ticket is
        // byte-identical (the state store retains the ORIGINAL expiry,
        // and a signed ticket can never outlive the chain state).
        $later = $clock + 900;
        $second = $service->ticket($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, $later);
        self::assertIsString($second);
        self::assertSame($first, $second, 'a repeated ticket() call against the same obligation returns a BYTE-IDENTICAL ticket');
        $payload2 = $service->verify($second);
        self::assertIsArray($payload2);
        self::assertSame((string) $payload1['chainId'], (string) $payload2['chainId'], 'both tickets carry the same chain id');
        self::assertSame($expiryX, (int) $payload2['expiresAt'], 'the signed expiry is the requirement\'s ORIGINAL expiry — never the later requested one');
        self::assertNotSame($later, (int) $payload2['expiresAt'], 'the later requested expiry must never leak into the signed ticket');

        // A THIRD call with yet another requested expiry: still
        // byte-identical.
        $third = $service->ticket($this->nonce(), 'login', 'txn-alpha', 1, RiskAction::Argon32, $clock + 1500);
        self::assertIsString($third);
        self::assertSame($first, $third, 'every repeated call against the same obligation returns the byte-identical ticket');

        // The server-held requirement never moved: the chain state keeps
        // the ORIGINAL expiry, and exactly ONE chain record exists.
        $requirement = $service->requirementFor((string) $payload1['chainId']);
        self::assertNotNull($requirement);
        self::assertSame($expiryX, $requirement->expiresAt, 'the chain state retains the ORIGINAL expiry');
        self::assertCount(1, (new \ReflectionObject($store))->getProperty('records')->getValue($store), 'the repeated calls never create a second chain');
    }

    public function testTicketForReconstructsTheExactTicketTheConvenienceSigned(): void
    {
        $clock = 1000;
        ['service' => $service] = $this->pinnedService($clock);
        $requested = $clock + 300;

        $ticket = $service->ticket($this->nonce(), 'login', '', 1, RiskAction::Argon32, $requested);
        self::assertIsString($ticket);
        $payload = $service->verify($ticket);
        self::assertIsArray($payload);

        // The deterministic reconstruction from the server-held pair
        // (chainId, expiresAt) reproduces the convenience ticket exactly.
        self::assertSame($ticket, $service->ticketFor((string) $payload['chainId'], (int) $payload['expiresAt']), 'the convenience ticket is the deterministic ticket of the requirement\'s (chainId, expiry) pair');
    }

    public function testRequirementForRetainsTheOriginalExpiryAfterVerification(): void
    {
        // THE VERIFIED-CHAIN LIVENESS READ the validator's CHAIN_REQUIRED
        // signing relies on: after the chain VERIFIES (its obligation is
        // cleared) the chain RECORD is retained with its ORIGINAL expiry —
        // requirementFor (the by-chain-id read, never the obligation
        // lookup) still resolves it, so a completed chain keeps re-signing
        // the deterministic ticket from the disposition-carried bound.
        $clock = 1000;
        ['store' => $store, 'service' => $service] = $this->pinnedService($clock);
        $expiryX = $clock + 300;
        $nonce = $this->nonce();

        $requirement = $service->requireStage2($nonce, 'login', 'txn-alpha', 1, RiskAction::Argon32, $expiryX);
        $ticket = $service->ticketFor($requirement->chainId, $requirement->expiresAt);
        self::assertIsString($ticket);

        // The chain issues and VERIFIES (the obligation is deleted — the
        // findOpenRequirement lookup now finds nothing).
        $stage2Nonce = base64_encode(hash('sha256', 'stage2', true));
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $stage2Nonce));
        self::assertSame(\BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::VerifiedNew, $service->markVerified($requirement->chainId, $stage2Nonce));
        self::assertNull($service->findOpenRequirement('login', 'txn-alpha', 1), 'the verified transition cleared the obligation');

        // The chain RECORD survives with the ORIGINAL expiry: the
        // by-chain-id read resolves the requirement and the deterministic
        // ticket is byte-identical.
        $retained = $service->requirementFor($requirement->chainId);
        self::assertNotNull($retained, 'the verified chain record is retained');
        self::assertSame('verified', $retained->state);
        self::assertSame($expiryX, $retained->expiresAt, 'the retained record keeps the ORIGINAL expiry');
        self::assertSame($ticket, $service->ticketFor($requirement->chainId, $retained->expiresAt), 'the completed chain re-signs the byte-identical ticket from its ORIGINAL expiry');
    }
}
