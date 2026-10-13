<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpKeyRing;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use PHPUnit\Framework\TestCase;

/**
 * The step-up HMAC key-rotation contract (stepUpKid): one current
 * signing key, historical verification keys that outlive the maximum
 * demand lifetime, and revoked kids that fail even when their secret is
 * still configured. The cross-node requirement — node A mints under the
 * old key, node B finalizes after rotating — is the central scenario.
 */
final class StepUpKeyRingTest extends TestCase
{
    private const MASTER_V1 = 'step-up-master-kid-1-aaaaaaaaaaaaaaaaaaaa';
    private const MASTER_V2 = 'step-up-master-kid-2-bbbbbbbbbbbbbbbbbbbb';
    private const MASTER_V3 = 'step-up-master-kid-3-cccccccccccccccccccc';

    private const CHALLENGE = 'AAAAAAAAAAAAAAAAAAAA';

    public function testIssueStampsTheCurrentKidAndVerifyRoundTrips(): void
    {
        $ring = new StepUpKeyRing(2, [1 => self::MASTER_V1, 2 => self::MASTER_V2]);
        $ticket = new StepUpTicket($ring);

        self::assertSame(2, $ticket->currentKid());

        $issued = $ticket->issue(self::CHALLENGE, 2_000_000_000);
        $payload = $ticket->verify($issued, 1_999_999_000);

        self::assertNotNull($payload);
        self::assertSame(self::CHALLENGE, $payload['challengeId']);
        self::assertSame(2_000_000_000, $payload['expiresAt']);
        self::assertSame(2, $payload['stepUpKid'], 'the signed payload must carry the minting stepUpKid');
    }

    /**
     * The cross-node rotation requirement: node A mints a ticket under
     * its original kid; the ring rotates (current becomes kid 2, kid 1
     * stays historical); node B (already rotated) still finalizes. The
     * historical key is valid for verification for at least the maximum
     * demand lifetime.
     */
    public function testNodeAMintsWithTheOldKeyAndNodeBFinalizesAfterRotation(): void
    {
        // Node A: pre-rotation ring, current kid 1.
        $nodeA = new StepUpTicket(new StepUpKeyRing(1, [1 => self::MASTER_V1]));
        $issued = $nodeA->issue(self::CHALLENGE, 2_000_000_000);
        self::assertSame(1, $nodeA->currentKid());

        // Rotation: kid 2 becomes current, kid 1 demoted to historical
        // (kept for the maximum demand lifetime).
        $nodeB = new StepUpTicket(new StepUpKeyRing(
            2,
            [1 => self::MASTER_V1, 2 => self::MASTER_V2],
        ));

        $payload = $nodeB->verify($issued, 1_999_999_000);
        self::assertNotNull($payload, 'HOLE: a historical kid failed to finalize after rotation');
        self::assertSame(1, $payload['stepUpKid'], 'the finalize must report the minting kid, not the current one');
        self::assertSame(self::CHALLENGE, $payload['challengeId']);
    }

    public function testARevokedKidFailsEvenWhenItsSecretIsStillConfigured(): void
    {
        $nodeB = new StepUpTicket(new StepUpKeyRing(
            2,
            [1 => self::MASTER_V1, 2 => self::MASTER_V2],
            [1], // kid 1 compromised
        ));

        // Mint under kid 1 on the pre-rotation node.
        $nodeA = new StepUpTicket(new StepUpKeyRing(1, [1 => self::MASTER_V1]));
        $issued = $nodeA->issue(self::CHALLENGE, 2_000_000_000);

        self::assertNull(
            $nodeB->verify($issued, 1_999_999_000),
            'HOLE: a revoked stepUpKid verified because its secret was still configured',
        );
    }

    public function testAnUnknownOrFutureKidFailsClosed(): void
    {
        $ring = new StepUpKeyRing(2, [1 => self::MASTER_V1, 2 => self::MASTER_V2]);
        $ticket = new StepUpTicket($ring);

        // A ticket stamped with kid 3 (future / unknown) under whatever
        // key must not fall back to the current key.
        $forged = self::forgeKid3($ticket);

        self::assertNull(
            $ticket->verify($forged, 1_999_999_000),
            'HOLE: a future/unknown stepUpKid fell back to the current key',
        );
    }

    public function testOneKidsCompromiseNeverForgesAnotherKid(): void
    {
        // Two independent rings sharing kid ids but not secrets: a ticket
        // minted under node A's kid 1 must not verify on node B's kid 1
        // when the masters differ.
        $nodeA = new StepUpTicket(new StepUpKeyRing(1, [1 => self::MASTER_V1]));
        $nodeB = new StepUpTicket(new StepUpKeyRing(1, [1 => self::MASTER_V3]));

        $issued = $nodeA->issue(self::CHALLENGE, 2_000_000_000);
        self::assertNull($nodeB->verify($issued, 1_999_999_000));
    }

    public function testTheLegacySingleMasterShapeStillRoundTrips(): void
    {
        $legacy = new StepUpTicket(self::MASTER_V1);
        self::assertSame(1, $legacy->currentKid());

        $issued = $legacy->issue(self::CHALLENGE, 2_000_000_000);
        $payload = $legacy->verify($issued, 1_999_999_000);

        self::assertNotNull($payload);
        self::assertSame(1, $payload['stepUpKid']);
    }

    public function testHistoricalKidsAreTheConfiguredSetMinusTheCurrent(): void
    {
        $ring = new StepUpKeyRing(
            3,
            [1 => self::MASTER_V1, 2 => self::MASTER_V2, 3 => self::MASTER_V3],
            [2],
        );

        self::assertSame(3, $ring->currentKid());
        self::assertSame([1, 2], $ring->historicalKids());
        self::assertSame([2], $ring->revokedKids());
        self::assertTrue($ring->isRevoked(2));
        self::assertNull($ring->resolve(2), 'a revoked kid must not resolve');
        self::assertNotNull($ring->resolve(1), 'a historical kid must resolve for verification');
        self::assertNotNull($ring->resolve(3));
        self::assertNull($ring->resolve(4), 'a future kid must not resolve');
    }

    public function testTheRingRefusesAnInvalidShape(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpKeyRing(1, []);
    }

    public function testTheRingRefusesAShortMaster(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpKeyRing(1, [1 => 'short']);
    }

    public function testTheRingRefusesARevokedCurrentKid(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpKeyRing(1, [1 => self::MASTER_V1], [1]);
    }

    public function testTheRingRefusesACurrentKidWithoutASecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new StepUpKeyRing(2, [1 => self::MASTER_V1]);
    }

    /**
     * A structurally valid ticket whose signed payload names kid 3 (a
     * kid no configured ring knows), signed under a throwaway key: the
     * verifier must refuse it rather than fall back.
     */
    private function forgeKid3(StepUpTicket $honest): string
    {
        // Build the version-2 body with kid 3 and re-sign under kid 3's
        // would-be master (any 32-byte secret) — the honest ring has no
        // such kid, so verification must refuse before trusting it.
        $body = rtrim(strtr(base64_encode((string) json_encode([2, self::CHALLENGE, 2_000_000_000, 3], JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $key = hash_hkdf('sha256', self::MASTER_V3, 32, 'kiwi/v1/stepup-ticket', 'kiwicaptcha/deploy-salt/v1');
        $sig = rtrim(strtr(base64_encode(hash_hmac('sha256', $body, $key, true)), '+/', '-_'), '=');

        return $body.'.'.$sig;
    }
}
