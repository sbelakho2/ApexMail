<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemand;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpDemandState;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpOperationDigest;
use PHPUnit\Framework\TestCase;

/**
 * The supersession fault and retry matrix of the escalation script,
 * on a real Predis client against a live redis-server (KC_REDIS_URL).
 * The Lua supersede is atomic, so the provable invariant is: only the
 * complete pre-supersede state (parent live and unmarked, child
 * absent) or the complete post-supersede state (parent marked with
 * the child link, child present, family index repointed) ever
 * persists. Never an intermediate. The matrix proves the retry
 * semantics, the different-child refusal and the terminal-state
 * guard. It walks the raw records around every phase of the
 * escalation, and replays a lost reply through a raw script
 * invocation. It proves the family lifetime inheritance, and walks
 * the dead end of the superseded parent through the full public
 * surface and the raw settle path.
 *
 * The leg owns the {kiwi:supmx}:stepup: hash-tagged family only. The
 * setup and teardown sweep exactly that family, the same isolation
 * discipline the other real-client legs use, so the sweep can never
 * reach another suite's keys on a shared instance.
 */
final class RedisStepUpSupersessionFaultMatrixRealPredisTest extends TestCase
{
    private const PREFIX = '{kiwi:supmx}:stepup:';

    private const TTL = 600;

    private \Predis\Client $client;

    private RedisStepUpChallengeStore $store;

    private int $now = 0;

    protected function setUp(): void
    {
        $url = getenv('KC_REDIS_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('KC_REDIS_URL not set — supersession fault matrix leg skipped');
        }
        if (!class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis not installed');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 2.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            self::markTestSkipped('Redis unreachable: '.$e->getMessage());
        }
        $this->store = new RedisStepUpChallengeStore($this->client, self::PREFIX);
        $this->now = time();
        $this->sweep();
    }

    protected function tearDown(): void
    {
        if (!isset($this->client)) {
            return;
        }
        try {
            $this->sweep();
        } catch (\Throwable) {
            // a dead instance must not fail the shutdown path
        }
    }

    private function sweep(): void
    {
        $keys = $this->client->keys(self::PREFIX.'*');
        if ($keys !== []) {
            $this->client->del(...$keys);
        }
    }

    // ── 1: the retry of the exact supersede call ────────────────────

    public function testARetryOfTheExactSupersedeCallAnswersNullAndPersistsNothing(): void
    {
        $parentId = 'mxretryparentid000000001';
        $childId = 'mxretrychildid000000001';
        $digest = $this->createParent($parentId, 'login');

        $child = $this->spawnChild($parentId, $childId);
        self::assertNotNull($this->store->supersedeDemandWithChild($parentId, $child), 'the first escalation of the live parent wins');
        $parentRaw = $this->raw($parentId);
        $childRaw = $this->raw($childId);
        $indexRaw = $this->rawIndex($digest);
        $familyKeys = $this->familyKeys();

        // The lost-reply replay: the exact same call, same child id.
        $retry = $this->store->supersedeDemandWithChild($parentId, $child);

        self::assertNull($retry, 'retry 1: the exact supersede call must answer null because the child key exists and refuses');
        self::assertSame($parentRaw, $this->raw($parentId), 'retry 1: the persisted parent record is byte-identical after the refused retry');
        self::assertSame($childRaw, $this->raw($childId), 'retry 1: the persisted child record is byte-identical after the refused retry');
        self::assertSame($indexRaw, $this->rawIndex($digest), 'retry 1: the family index is byte-identical after the refused retry');
        self::assertCount(2, $this->familyKeys(), 'retry 1: exactly one child exists, the retry minted no second child');
        self::assertSame($childId, $this->store->readDemand($parentId)?->supersededByDemandId, 'retry 1: the parent names exactly the first child');
        self::assertSame($familyKeys, $this->familyKeys(), 'retry 1: the family membership is unchanged');
        self::assertSame($childId, $this->store->demandIdForOperation($digest), 'retry 1: the family index still names the first child');

        // A second retry after the first: identical refusal, identical state.
        self::assertNull($this->store->supersedeDemandWithChild($parentId, $child), 'retry 2: the exact supersede call answers null again');
        self::assertSame($parentRaw, $this->raw($parentId), 'retry 2: the parent record is still byte-identical');
        self::assertCount(2, $this->familyKeys(), 'retry 2: a lost-reply retry never mints a second child');
    }

    // ── 2: the second escalation with a different child ─────────────

    public function testASecondEscalationWithADifferentChildRefusesAndWritesNothing(): void
    {
        $parentId = 'mxsecondparentid00000001';
        $childId = 'mxsecondchildid000000001';
        $digest = $this->createParent($parentId, 'signup');

        $child = $this->spawnChild($parentId, $childId);
        self::assertNotNull($this->store->supersedeDemandWithChild($parentId, $child), 'the first escalation wins');
        $parentRaw = $this->raw($parentId);
        $childRaw = $this->raw($childId);
        $indexRaw = $this->rawIndex($digest);

        $siblingId = 'mxsecondsiblingid0000001';
        $sibling = $this->spawnChild($parentId, $siblingId);
        $second = $this->store->supersedeDemandWithChild($parentId, $sibling);

        self::assertNull($second, 'second 1: an already superseded parent refuses a second escalation with a different child');
        self::assertNull($this->raw($siblingId), 'second 1: the refused sibling was never written to the store');
        self::assertNull($this->store->readDemand($siblingId), 'second 1: the refused sibling reads as absent');
        self::assertSame($parentRaw, $this->raw($parentId), 'second 1: the parent record is byte-identical');
        self::assertSame($childRaw, $this->raw($childId), 'second 1: the first child record is byte-identical');
        self::assertSame($indexRaw, $this->rawIndex($digest), 'second 1: the family index still names the first child');
        self::assertCount(2, $this->familyKeys(), 'second 1: no second child was written');
    }

    // ── 3: the terminal-state guard ─────────────────────────────────

    public function testASupersedeAgainstATerminalParentRefusesForEveryTerminalState(): void
    {
        // authorized: the settled authorization is history.
        $authId = 'mxtermauthparentid0000001';
        $authDigest = $this->createParent($authId, 'signup_confirm');
        self::assertNotNull($this->store->completeDemand($authId, $this->now, self::TTL), 'terminal 1: the authorized parent completed');
        self::assertNotNull($this->store->claimDemandFinalization($authId, $this->now, 30), 'terminal 1: the authorized parent was claimed');
        self::assertNotNull($this->store->settleDemandFinalization($authId, StepUpDemandState::Authorized, $this->now), 'terminal 1: the authorized terminal settled');
        $this->assertRefusedSupersede($authId, 'mxtermauthchildid0000001', $authDigest, 'authorized');

        // denied: the refused terminal is history too.
        $deniedId = 'mxtermdeniedparentid00001';
        $deniedDigest = $this->createParent($deniedId, 'signup_email');
        self::assertNotNull($this->store->completeDemand($deniedId, $this->now, self::TTL), 'terminal 2: the denied parent completed');
        self::assertNotNull($this->store->claimDemandFinalization($deniedId, $this->now, 30), 'terminal 2: the denied parent was claimed');
        self::assertNotNull($this->store->settleDemandFinalization($deniedId, StepUpDemandState::Denied, $this->now), 'terminal 2: the denied terminal settled');
        $this->assertRefusedSupersede($deniedId, 'mxtermdeniedchildid000001', $deniedDigest, 'denied');

        // completed: mid-finalization, never a family head.
        $completedId = 'mxtermcompletedparentid001';
        $completedDigest = $this->createParent($completedId, 'signup');
        self::assertNotNull($this->store->completeDemand($completedId, $this->now, self::TTL), 'terminal 3: the completed parent completed');
        $this->assertRefusedSupersede($completedId, 'mxtermcompletedchildid01', $completedDigest, 'completed');

        // superseded: the marker of the first escalation refuses any
        // further escalation of the same parent.
        $supersededId = 'mxtermsupersededparentid1';
        $supersededDigest = $this->createParent($supersededId, 'login');
        $firstChild = $this->spawnChild($supersededId, 'mxtermsupersededchild001');
        self::assertNotNull($this->store->supersedeDemandWithChild($supersededId, $firstChild), 'terminal 4: the first escalation of the live parent wins');
        $this->assertRefusedSupersede($supersededId, 'mxtermsupersededchild002', $supersededDigest, 'superseded');
    }

    /**
     * One terminal-state probe: snapshot the parent, attempt the
     * supersede with a fresh child, assert the refusal, the absent
     * child and the byte-identical parent record.
     */
    private function assertRefusedSupersede(string $parentId, string $childId, string $digest, string $label): void
    {
        $parentRaw = $this->raw($parentId);
        $child = $this->spawnChild($parentId, $childId);
        $answer = $this->store->supersedeDemandWithChild($parentId, $child);

        self::assertNull($answer, 'terminal '.$label.': the supersede must answer null against a parent in the '.$label.' state');
        self::assertNull($this->raw($childId), 'terminal '.$label.': the refused child was never written');
        self::assertNull($this->store->readDemand($childId), 'terminal '.$label.': the refused child reads as absent');
        self::assertSame($parentRaw, $this->raw($parentId), 'terminal '.$label.': the parent record is byte-identical after the refusal');
        self::assertStringNotContainsString('"superseded_by":"'.$childId.'"', (string) $this->raw($parentId), 'terminal '.$label.': the parent never carries the refused child link');
        $this->assertTwoRecordState($parentId, $childId, $digest, 'terminal '.$label);
    }

    // ── 4: the boundary walk ────────────────────────────────────────

    /**
     * A crash cannot split a Lua script from PHP, so the boundary walk
     * proves the equivalent. Around every phase of the escalation the
     * raw two-record state is inspected, and only the complete
     * pre-supersede state or the complete post-supersede state is ever
     * observed. A state where the child exists while the parent lacks
     * the link, or the parent carries the link while the child is
     * absent, would fail the invariant here.
     */
    public function testTheBoundaryWalkPersistsOnlyTheCompletePreOrPostState(): void
    {
        $parentId = 'mxboundaryparentid000001';
        $childId = 'mxboundarychildid0000001';
        $digest = $this->createParent($parentId, 'signup');

        // Boundary phase: before the call, the complete pre-state.
        $this->assertTwoRecordState($parentId, $childId, $digest, 'boundary before the call');
        self::assertNull($this->raw($childId), 'boundary: the child key is absent before the call');
        $parentRecord = $this->rawRecord($parentId);
        self::assertNull($parentRecord['superseded_by'] ?? null, 'boundary: the parent carries no child link before the call');

        $child = $this->spawnChild($parentId, $childId);
        self::assertNotNull($this->store->supersedeDemandWithChild($parentId, $child), 'boundary: the escalation of the live parent wins');

        // Boundary phase: immediately after the call, the complete
        // post-state, all three writes observable in one inspection.
        $this->assertTwoRecordState($parentId, $childId, $digest, 'boundary after the call');
        self::assertSame($childId, $this->rawRecord($parentId)['superseded_by'] ?? null, 'boundary: the parent record names the child');
        self::assertSame($childId, $this->rawIndex($digest), 'boundary: the family index names the child');
        self::assertSame((string) $this->now, (string) ($this->rawRecord($childId)['created_at'] ?? ''), 'boundary: the child carries the server-stamped created_at');
        self::assertSame($parentId, $this->rawRecord($childId)['parent_demand_id'] ?? null, 'boundary: the child names its parent');

        // The refused retry leaves the post-state exactly as it was.
        self::assertNull($this->store->supersedeDemandWithChild($parentId, $child), 'boundary: the retry of the exact call refuses');
        $this->assertTwoRecordState($parentId, $childId, $digest, 'boundary after the refused retry');

        // A second boundary walk through a raw lost reply: the state
        // jumps from the complete pre-state to the complete post-state
        // in one script invocation, the same atomic step.
        $lostId = 'mxboundaryparentid000002';
        $lostChildId = 'mxboundarychildid0000002';
        $lostDigest = $this->createParent($lostId, 'signup_email');
        $this->assertTwoRecordState($lostId, $lostChildId, $lostDigest, 'boundary 2 before the lost reply');
        $lostChild = $this->spawnChild($lostId, $lostChildId);
        $this->evalSupersede($lostId, $lostChild);
        $this->assertTwoRecordState($lostId, $lostChildId, $lostDigest, 'boundary 2 after the lost reply');
    }

    /**
     * The one invariant of the whole matrix, checked on the raw
     * records: exactly one of the two complete states persists.
     */
    private function assertTwoRecordState(string $parentId, string $childId, string $digest, string $label): void
    {
        $parentRecord = $this->rawRecord($parentId);
        $childRaw = $this->raw($childId);
        $index = $this->rawIndex($digest);
        $marked = \is_array($parentRecord) && ($parentRecord['superseded_by'] ?? null) === $childId;
        $pre = $childRaw === null && !$marked && $index !== $childId;
        $post = $childRaw !== null && $marked && $index === $childId;

        self::assertTrue($pre !== $post, $label.': exactly one of the complete pre-supersede or post-supersede states must persist (child='.\strlen((string) $childRaw).' bytes, marked='.(int) $marked.', index='.(string) $index.')');
        self::assertFalse($childRaw !== null && !$marked, $label.': a state where the child exists while the parent lacks the link must never persist');
        self::assertFalse($marked && $childRaw === null, $label.': a state where the parent carries the link while the child is absent must never persist');
        self::assertFalse($marked && $index !== $childId, $label.': a marked parent must always pair with the repointed family index');
    }

    // ── 5: the lost-reply simulation ────────────────────────────────

    public function testALostReplyPersistsTheNewStateAndTheWrapperRetryStaysANull(): void
    {
        $parentId = 'mxlostreplyparentid000001';
        $childId = 'mxlostreplychildid000001';
        $digest = $this->createParent($parentId, 'signup_confirm');
        $child = $this->spawnChild($parentId, $childId);

        // The reply is discarded: the caller cannot tell whether the
        // script ran. The raw state must have moved to the complete
        // post-supersede shape regardless.
        $this->evalSupersede($parentId, $child);

        self::assertSame($childId, $this->rawRecord($parentId)['superseded_by'] ?? null, 'lost reply: the raw parent record carries the child link');
        self::assertNotNull($this->raw($childId), 'lost reply: the raw child record exists');
        self::assertSame($childId, $this->rawIndex($digest), 'lost reply: the family index names the child');
        self::assertTrue((bool) $this->store->readDemand($parentId)?->superseded(), 'lost reply: the store reads the parent as superseded');
        self::assertNotNull($this->store->readDemand($childId), 'lost reply: the store reads the child as present');
        self::assertSame($childId, $this->store->demandIdForOperation($digest), 'lost reply: the family tip is the child');
        $parentRaw = $this->raw($parentId);
        $childRaw = $this->raw($childId);

        // The wrapper retry of the exact call: the child key exists and
        // refuses, the state is untouched.
        self::assertNull($this->store->supersedeDemandWithChild($parentId, $child), 'lost reply: the wrapper retry of the exact call answers null');
        self::assertSame($parentRaw, $this->raw($parentId), 'lost reply: the parent record is byte-identical after the wrapper retry');
        self::assertSame($childRaw, $this->raw($childId), 'lost reply: the child record is byte-identical after the wrapper retry');

        // A different child id: the marked parent refuses, nothing is
        // written.
        $sibling = $this->spawnChild($parentId, 'mxlostreplysiblingid0001');
        self::assertNull($this->store->supersedeDemandWithChild($parentId, $sibling), 'lost reply: the different-child escalation answers null against the marked parent');
        self::assertNull($this->raw('mxlostreplysiblingid0001'), 'lost reply: the sibling was never written');
        self::assertSame($parentRaw, $this->raw($parentId), 'lost reply: the parent record is byte-identical after the sibling attempt');
    }

    // ── 6: the family lifetime inheritance ──────────────────────────

    public function testTheChildNeverOutlivesTheFamilyLifetime(): void
    {
        $parentId = 'mxfamilyparentid000000001';
        $childId = 'mxfamilychildid000000001';
        $this->createParent($parentId, 'login');
        $parentKey = self::PREFIX.'emd:'.$parentId;
        $pttlBefore = (int) $this->client->pttl($parentKey);
        self::assertGreaterThan(0, $pttlBefore, 'family: the parent carries a live lifetime before the escalation');

        $child = $this->spawnChild($parentId, $childId);
        self::assertNotNull($this->store->supersedeDemandWithChild($parentId, $child), 'family: the escalation wins');

        $parentPttl = (int) $this->client->pttl($parentKey);
        $childPttl = (int) $this->client->pttl(self::PREFIX.'emd:'.$childId);
        self::assertGreaterThan(0, $childPttl, 'family: the child carries a live lifetime');
        self::assertGreaterThan(0, $parentPttl, 'family: the marked parent keeps its live lifetime');
        self::assertLessThanOrEqual($pttlBefore, $childPttl, 'family: the child lifetime never exceeds the parent lifetime the escalation inherited');
        self::assertLessThanOrEqual(50, abs($childPttl - $parentPttl), 'family: the child and the parent share the same remaining lifetime, within the millisecond decay between their writes; the script writes the child first, so its clock can read marginally larger');
        self::assertSame($this->rawRecord($parentId)['expires_at'], $this->rawRecord($childId)['expires_at'], 'family: the minted authorization deadline of the child equals the parent deadline exactly');

        // A forged child with a foreign expiry is refused outright
        // against a live parent, so a child can never extend the family
        // lifetime through the inheritance gate.
        $forgedParentId = 'mxfamilyforgedparent0001';
        $this->createParent($forgedParentId, 'signup');
        $forgedParentRaw = $this->raw($forgedParentId);
        $forged = StepUpDemand::mint('mxfamilyforgedchild00001', 'signup', null, null, 'decision-1', $this->now, self::TTL * 4);
        self::assertNull($this->store->supersedeDemandWithChild($forgedParentId, $forged), 'family: a child that outlives the inherited deadline refuses');
        self::assertNull($this->raw('mxfamilyforgedchild00001'), 'family: the forged child was never written');
        self::assertNull($this->store->readDemand('mxfamilyforgedchild00001'), 'family: the forged child reads as absent');
        self::assertSame($forgedParentRaw, $this->raw($forgedParentId), 'family: the live parent record is byte-identical after the refused escalation');
        self::assertNull($this->rawRecord($forgedParentId)['superseded_by'] ?? null, 'family: the live parent stays unmarked');
    }

    // ── 7: the superseded parent authorizes through nothing ─────────

    public function testTheSupersededParentAuthorizesThroughNoPublicOrRawPath(): void
    {
        // Shape 1: the escalation of an open parent.
        $openId = 'mxdeadendopenparentid0001';
        $openChildId = 'mxdeadendopenchildid0001';
        $this->createParent($openId, 'signup');
        $openChild = $this->spawnChild($openId, $openChildId);
        self::assertNotNull($this->store->supersedeDemandWithChild($openId, $openChild), 'dead end 1: the escalation wins');
        $openRaw = $this->raw($openId);

        self::assertNull($this->store->claimDemandFinalization($openId, $this->now, 30), 'dead end 1: the superseded parent is never claimed for finalization');
        self::assertNull($this->store->settleDemandFinalization($openId, StepUpDemandState::Authorized, $this->now), 'dead end 1: the superseded parent never settles authorized through the wrapper');
        self::assertNull($this->evalClaim($openId), 'dead end 1: the raw claim script answers nil for the superseded parent');
        self::assertNull($this->evalSettle($openId, 'authorized'), 'dead end 1: the raw settle script answers nil for the authorized terminal');
        self::assertNull($this->evalComplete($openId), 'dead end 1: the raw complete script answers nil for the superseded parent');
        self::assertSame($openRaw, $this->raw($openId), 'dead end 1: the parent record is byte-identical through every refused path');

        // Shape 2: the escalator holding its own claim. The supersede
        // transaction writes the whole terminal (state, stamp, marker)
        // in one step, so the parent stands superseded the moment the
        // script returns.
        $claimId = 'mxdeadendclaimparentid01';
        $claimChildId = 'mxdeadendclaimchildid001';
        $this->createParent($claimId, 'signup_email');
        self::assertNotNull($this->store->completeDemand($claimId, $this->now, self::TTL), 'dead end 2: the parent completed');
        self::assertNotNull($this->store->claimDemandFinalization($claimId, $this->now, 30), 'dead end 2: the escalator holds its claim');
        $claimChild = $this->spawnChild($claimId, $claimChildId);
        self::assertNotNull($this->store->supersedeDemandWithChild($claimId, $claimChild), 'dead end 2: the escalation of the claimed parent wins');
        $claimRaw = $this->raw($claimId);
        self::assertSame('superseded', $this->rawRecord($claimId)['state'] ?? '', 'dead end 2: the supersede transaction wrote the superseded terminal itself');

        self::assertNull($this->store->claimDemandFinalization($claimId, $this->now, 30), 'dead end 2: the marker refuses the claim');
        self::assertNull($this->store->settleDemandFinalization($claimId, StepUpDemandState::Authorized, $this->now), 'dead end 2: the wrapper settles nothing authorized on the superseded parent');
        self::assertNull($this->evalSettle($claimId, 'authorized'), 'dead end 2: the raw settle script refuses the authorized terminal against the marker');
        self::assertNull($this->evalClaim($claimId), 'dead end 2: the raw claim script answers nil against the marker');
        self::assertNull($this->evalComplete($claimId), 'dead end 2: the raw complete script answers nil against the marker');
        self::assertSame($claimRaw, $this->raw($claimId), 'dead end 2: the parent record is byte-identical through every refused path');

        // The superseded terminal is absorbing on the raw surface too:
        // no settlement of any kind lands past it, because the terminal
        // itself was the supersede transaction's output.
        self::assertNull($this->evalSettle($claimId, 'denied'), 'dead end 2: the raw denied settlement is refused past the terminal');
        self::assertNull($this->evalSettle($claimId, 'superseded'), 'dead end 2: a second superseded settlement is refused');
        self::assertNull($this->store->settleDemandFinalization($claimId, StepUpDemandState::Authorized, $this->now), 'dead end 2: the authorized settlement stays impossible');
    }

    // ── helpers ─────────────────────────────────────────────────────

    /** Mint and persist one open parent demand; answers its family digest. */
    private function createParent(string $id, string $scope): string
    {
        $demand = StepUpDemand::mint($id, $scope, null, null, 'decision-1', $this->now, self::TTL);
        $stored = $this->store->createDemand($demand, self::TTL);
        self::assertSame($id, $stored, 'the parent demand persists under its own id');

        return $demand->operationDigest;
    }

    /** The escalation child minted from the live parent record. */
    private function spawnChild(string $parentId, string $childId): StepUpDemand
    {
        $parent = $this->store->readDemand($parentId);
        self::assertNotNull($parent, 'the parent record is live before the child is spawned');

        return $parent->spawnChild($childId, $this->now, 'decision-2');
    }

    /** The raw record string of one demand key, null when absent. */
    private function raw(string $demandId): ?string
    {
        return $this->client->get(self::PREFIX.'emd:'.$demandId);
    }

    /** The raw decoded record of one demand key. */
    private function rawRecord(string $demandId): ?array
    {
        $raw = $this->raw($demandId);
        if ($raw === null) {
            return null;
        }
        $decoded = json_decode($raw, true);
        self::assertIsArray($decoded, 'the raw record of '.$demandId.' decodes');

        return $decoded;
    }

    private function rawIndex(string $digest): ?string
    {
        return $this->client->get(self::PREFIX.'emi:'.$digest);
    }

    /** @return list<string> */
    private function familyKeys(): array
    {
        $keys = $this->client->keys(self::PREFIX.'emd:*');
        sort($keys);

        return $keys;
    }

    /** The production supersede script body, read off the store class. */
    private function supersedeScript(): string
    {
        $script = (new \ReflectionClass(RedisStepUpChallengeStore::class))->getConstant('DEMAND_SUPERSEDE_SCRIPT');
        self::assertIsString($script, 'the escalation script constant is readable for the raw invocation');

        return (string) $script;
    }

    /** The production lifecycle script body, read off the store class. */
    private function transitionScript(): string
    {
        $script = (new \ReflectionClass(RedisStepUpChallengeStore::class))->getConstant('DEMAND_TRANSITION_SCRIPT');
        self::assertIsString($script, 'the lifecycle script constant is readable for the raw invocation');

        return (string) $script;
    }

    /**
     * Run the exact production supersede script directly against the
     * raw client, the bypass any store-side retry bookkeeping. The
     * reply is answered but the caller is expected to discard it.
     */
    private function evalSupersede(string $parentId, StepUpDemand $child): mixed
    {
        return $this->client->eval(
            $this->supersedeScript(),
            3,
            self::PREFIX.'emd:'.$parentId,
            self::PREFIX.'emd:'.$child->id,
            self::PREFIX.'emi:'.$child->operationDigest,
            (string) json_encode($child->toArray(), JSON_UNESCAPED_SLASHES),
            $child->id,
        );
    }

    private function evalTransition(string $demandId, string ...$args): mixed
    {
        return $this->client->eval($this->transitionScript(), 1, self::PREFIX.'emd:'.$demandId, ...$args);
    }

    private function evalClaim(string $demandId): mixed
    {
        return $this->evalTransition($demandId, 'claim', (string) $this->now, '30');
    }

    private function evalSettle(string $demandId, string $terminal): mixed
    {
        return $this->evalTransition($demandId, 'settle', $terminal, (string) $this->now, '');
    }

    private function evalComplete(string $demandId): mixed
    {
        return $this->evalTransition($demandId, 'complete', (string) $this->now, (string) self::TTL);
    }
}
