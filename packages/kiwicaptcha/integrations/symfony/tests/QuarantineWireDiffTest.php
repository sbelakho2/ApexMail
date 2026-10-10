<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ArrayPostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\QuarantineMarkerInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestQuarantineMarker;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Marks\StoreMarksReader;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\SignalVector;
use KiwiCaptcha\Risk\Storage\OutcomeMarksStoreInterface;
use KiwiCaptcha\Risk\Storage\RiskStateStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionContextTagStoreInterface;
use KiwiCaptcha\Risk\Storage\SessionTlsTagStoreInterface;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Validator\ValidatorInterface;

/**
 * The quarantine wire-diff harness (change.md 1.3 and 3.3.4). The
 * done-when is exact: a wire-diff harness cannot distinguish quarantine
 * from allow. Pairs of identities run the same inputs through the full
 * challenge + verify + submit path: one identity carries a
 * server-confirmed spamReported mark inside its TTL, the other is
 * clean. The harness asserts byte-identical HTTP on every challenge
 * leg, modulo the fields the protocol itself varies.
 *
 * The volatile set is learned, never assumed: control pairs of two
 * clean identities establish exactly which body keys and headers vary
 * between two ordinary allow responses (the issuance randomness: nonce,
 * challenge, salt, prefix, plus the response Date header). Every
 * marked-vs-clean diff must then be empty outside that learned set, and
 * the difficulty-bearing fields (algorithm, targetBits, mKib, t, p,
 * ttlSecs, minDurationMs) are asserted equal without any normalization,
 * so a quarantine that moved the rung or the pricing fails loudly. The
 * timing noise floor is measured the same way, from the control pairs.
 *
 * The flag itself is server-side only: the submit leg processes with
 * HTTP-200-class behavior (zero violations, the form would submit) and
 * the request attribute kiwi.quarantine plus the marker hold are set for
 * exactly the marked half, never for the clean half. No browser-visible
 * surface may carry the flag: the bundle emits no kiwi.* response header
 * anywhere, and the assert below pins that.
 */
final class QuarantineWireDiffTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** N = 2k paired requests: 1000 marked and 1000 clean, same inputs. */
    private const PairCount = 1000;

    /** The interleaved control pairs (two clean legs) inside the loop. */
    private const ControlPairs = 10;

    private const SESSION_COOKIE = '__Host-kiwi-session';
    private const MARKED_SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1';
    private const CLEAN_SESSION = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02';
    private const CONTROL_A_SESSION = 'cccccccccccccccccccccccccccccc03';
    private const CONTROL_B_SESSION = 'dddddddddddddddddddddddddddddd04';

    /** The body keys the issuance randomness varies between two allows. */
    private const VOLATILE_BODY_KEYS = ['challenge', 'nonce', 'prefix', 'salt'];

    /** The difficulty and lifetime fields, never normalized away. */
    private const DIFFICULTY_KEYS = ['algorithm', 'minDurationMs', 'mKib', 'p', 't', 'targetBits', 'ttlSecs'];

    public function testQuarantineIsWireIndistinguishableFromAllowEndToEnd(): void
    {
        $harness = $this->harness();
        $this->markSession($harness, self::MARKED_SESSION);

        // The control phase: pairs of two clean identities learn the
        // volatile body keys, the volatile headers and the timing noise
        // floor. Any key outside the issuance randomness that differs
        // between two ordinary allows is a wire difference the protocol
        // does not own.
        $control = $this->learnVolatility($harness);
        $reference = $control['reference'];

        $markedDeltasMs = [];
        $floorDeltasMs = $control['deltasMs'];
        $markedHeld = 0;
        for ($i = 0; $i < self::PairCount; ++$i) {
            // Every hundredth pair is a control pair (two clean legs):
            // the noise-floor samples interleave with the measured legs,
            // so both sides of the timing comparison see the same machine
            // load and the floor cannot drift away under a loaded suite.
            $controlPair = $i % 100 === 50;
            if ($controlPair) {
                $first = $this->challengeLeg($harness, self::CONTROL_A_SESSION);
                $clean = $this->challengeLeg($harness, self::CONTROL_B_SESSION);
                $floorDeltasMs[] = abs($first['ms'] - $clean['ms']);
            } else {
                $marked = $this->challengeLeg($harness, self::MARKED_SESSION);
                $clean = $this->challengeLeg($harness, self::CLEAN_SESSION);
            }

            // Status, header set and the difficulty-bearing fields must
            // be exactly the allow shape, before any normalization.
            $this->assertSame(200, $marked['status']);
            $this->assertSame(200, $clean['status']);
            foreach ([$marked, $clean] as $leg) {
                foreach (self::DIFFICULTY_KEYS as $key) {
                    $this->assertSame($reference[$key], $leg['body'][$key], "quarantine must not move {$key}");
                }
                $this->assertSame(
                    array_keys($control['referenceHeaders']),
                    array_keys($leg['headers']),
                    'the header set is identical to allow',
                );
            }
            // Byte equality modulo the learned volatility, for the
            // marked leg against the clean control reference AND the
            // clean leg against itself.
            $this->assertSame($this->normalize($reference), $this->normalize($clean['body']), 'the clean leg self-diff must be empty');
            $this->assertSame(
                $this->normalize($reference),
                $this->normalize($marked['body']),
                'the marked challenge response differs from allow outside the issuance randomness',
            );
            foreach ($control['volatileHeaders'] as $name) {
                unset($marked['headers'][$name], $clean['headers'][$name]);
            }
            $this->assertSame($clean['headers'], $marked['headers'], 'the non-volatile headers must be byte-identical');

            // A control pair has no marked leg: its two clean legs have
            // already asserted the byte shape above.
            if ($controlPair) {
                continue;
            }
            // The submit legs: both halves process exactly like an
            // allow; the server-side hold rides exactly the marked one.
            $markedDeltasMs[] = abs($marked['ms'] - $clean['ms']);
            $markedSubmit = $this->submitLeg($harness, self::MARKED_SESSION, $marked['body']);
            $cleanSubmit = $this->submitLeg($harness, self::CLEAN_SESSION, $clean['body']);
            $this->assertSame(0, $markedSubmit['violations'], 'a quarantined submission processes exactly like an allow');
            $this->assertSame(0, $cleanSubmit['violations']);
            $this->assertTrue($markedSubmit['held'], 'the marked half must carry the server-side quarantine hold');
            $this->assertFalse($cleanSubmit['held'], 'the clean half must never carry a hold');
            $this->assertTrue($markedSubmit['attribute'], 'the kiwi.quarantine request attribute rides the marked half');
            $this->assertFalse($cleanSubmit['attribute']);
            ++$markedHeld;
        }
        // The ten interleaved control pairs carry no marked leg.
        $this->assertSame(self::PairCount - self::ControlPairs, $markedHeld, 'the hold is set for exactly the marked half');

        // The metrics plane counts the disposition as its own action
        // label: exactly one quarantine decision per leg per plane, while
        // the wire decisions stay allow-shaped.
        $counters = $harness['engine']->metrics()->snapshot()['counters'];
        $quarantineTotal = 0;
        $allowTotal = 0;
        foreach ($counters as $name => $count) {
            if (str_starts_with($name, 'decisions:1:quarantine:')) {
                $quarantineTotal += $count;
            }
            if (str_starts_with($name, 'decisions:1:allow:')) {
                $allowTotal += $count;
            }
        }
        $this->assertSame((self::PairCount - self::ControlPairs) * 2, $quarantineTotal, 'each marked pair quarantines on pre-issue and post-solve');
        // The clean total covers the measured clean pairs (pre-issue and
        // post-solve each) plus every control-phase and interleaved
        // control leg (pre-issue only).
        $this->assertSame(
            (self::PairCount - self::ControlPairs) * 2 + self::ControlPairs * 2 + 20,
            $allowTotal,
            'every clean assessment scores the plain allow label',
        );

        // The timing noise floor is measured from the interleaved clean
        // control pairs, so both distributions sample the same load. The
        // medians must agree and the marked p95 must stay within the
        // documented slack over the floor sample (a sample, not a bound).
        $floorMedian = $this->percentile($floorDeltasMs, 0.5);
        $floorP95 = $this->percentile($floorDeltasMs, 0.95);
        $markedMedian = $this->percentile($markedDeltasMs, 0.5);
        $markedP95 = $this->percentile($markedDeltasMs, 0.95);
        $this->assertLessThanOrEqual(
            max($floorMedian * 3.0, $floorMedian + 1.0),
            $markedMedian,
            sprintf(
                'the marked-vs-clean median leg delta (%.3f ms) exceeds the measured allow noise floor (%.3f ms)',
                $markedMedian,
                $floorMedian,
            ),
        );
        $this->assertLessThanOrEqual(
            max($floorP95 * 5.0, $floorP95 + 5.0),
            $markedP95,
            sprintf(
                'the marked-vs-clean leg p95 (%.3f ms) exceeds the measured allow noise floor p95 (%.3f ms)',
                $markedP95,
                $floorP95,
            ),
        );

        // The persisted hold: a replay of the same logical operation
        // (explicit server-owned operation id) reproduces the stored
        // quarantined pass instead of publishing on the retry.
        $this->replayReproducesTheHold($harness, $reference);
    }

    /**
     * The hold helper contract: request-scoped, never a wire surface,
     * and safe without a request in scope.
     */
    public function testMarkerIsRequestScopedAndNeverWireVisible(): void
    {
        $stack = new RequestStack();
        $marker = new RequestQuarantineMarker($stack);
        $this->assertFalse($marker->isHeld(), 'no request in scope: no hold');
        $request = Request::create('/', 'POST');
        $stack->push($request);
        $this->assertFalse($marker->isHeld());
        $marker->hold();
        $this->assertTrue($marker->isHeld());
        $this->assertTrue($marker->isHeldOn($request));
        $this->assertTrue($request->attributes->get(QuarantineMarkerInterface::ATTRIBUTE) === true);
        // The attribute plane is server-side only: no kiwi.* response
        // header and no cookie may ever exist on a response.
        $response = new Response('ok');
        foreach (array_keys($response->headers->all()) as $name) {
            $this->assertStringNotContainsString('kiwi', strtolower((string) $name), 'no kiwi.* response header may exist');
        }
        $this->assertCount(0, $response->headers->getCookies());
        // A second request never inherits the hold.
        $stack->pop();
        $stack->push(Request::create('/', 'POST'));
        $this->assertFalse($marker->isHeld(), 'a long-running worker never leaks one request hold into the next');
    }

    /**
     * @return array{reference: array<string, mixed>, referenceHeaders: array<string, string>, volatileHeaders: list<string>, deltasMs: list<float>}
     */
    private function learnVolatility(array $harness): array
    {
        $volatile = [];
        $volatileHeaders = [];
        $deltasMs = [];
        $reference = null;
        $referenceHeaders = null;
        for ($i = 0; $i < 10; ++$i) {
            $a = $this->challengeLeg($harness, self::CONTROL_A_SESSION);
            $b = $this->challengeLeg($harness, self::CONTROL_B_SESSION);
            // Two consecutive same-shape control legs: their wall-time
            // spread is the timing noise floor sample of this iteration.
            $deltasMs[] = abs($a['ms'] - $b['ms']);
            if ($reference === null) {
                $reference = $b['body'];
                $referenceHeaders = $b['headers'];
            } else {
                $this->assertSame(
                    $this->normalize($reference),
                    $this->normalize($b['body']),
                    'two clean iterations must normalize to one byte-shape',
                );
            }
            $this->assertSame(array_keys($a['body']), array_keys($b['body']), 'two allow responses must share one body key set');
            foreach (array_keys($a['body']) as $key) {
                if ($a['body'][$key] !== $b['body'][$key]) {
                    $volatile[$key] = true;
                }
            }
            $this->assertSame(array_keys($a['headers']), array_keys($b['headers']), 'two allow responses must share one header set');
            foreach ($a['headers'] as $name => $value) {
                if ($value !== $b['headers'][$name]) {
                    $volatileHeaders[$name] = true;
                }
            }
        }
        ksort($volatile);
        ksort($volatileHeaders);
        $this->assertSame(
            self::VOLATILE_BODY_KEYS,
            array_keys($volatile),
            'the protocol-varied key set of the challenge response changed; re-derive the harness volatile set',
        );

        return [
            'reference' => $reference,
            'referenceHeaders' => $referenceHeaders,
            'volatileHeaders' => array_keys($volatileHeaders),
            'deltasMs' => $deltasMs,
        ];
    }

    /**
     * @return array{
     *     marks: MarksStore,
     *     engine: AdaptiveRiskEngine,
     *     controller: ChallengeController,
     *     stack: RequestStack,
     *     validate: ValidatorInterface,
     *     dtoClass: string,
     *     marker: RequestQuarantineMarker,
     * }
     */
    private function harness(): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'sha16', 2 => 'sha18', 3 => 'sha20', 4 => 'sha20'],
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => true, 'degraded' => 'allow'],
            ],
        ]);
        $store = new MarksStore();
        $engine = new AdaptiveRiskEngine(
            $store,
            $classifier,
            new RiskIdentityFactory($keys),
            new RiskScorer(),
            $policy,
            $keys,
            marksReader: new StoreMarksReader($store),
            // The harness runs thousands of assessments within one
            // process second: the default emergency cap's warm-up ramp
            // (a tenth of the cap for the first ten seconds) would
            // hard-deny legs that have nothing to do with quarantine.
            limiter: new \KiwiCaptcha\Risk\Storage\ProcessEmergencyCap(100000, 0.0),
        );
        $stack = new RequestStack();
        $gateway = new RiskGateway(
            $engine,
            $classifier,
            new RiskProfileResolver(PoWAlgorithm::Sha256, 8),
            ['login' => 1],
            null,
            null,
            ['login' => true],
            'reject',
            null,
            null,
            $stack,
            null,
            '{kiwi:wire-diff}:decision:',
            300,
            $policy,
        );
        $storage = new ArrayStorage();
        // minDurationMs 0 keeps the verify legs free of the solve-floor
        // sleep: the noise floor measures the pipeline, not a delay.
        $config = new Config(secretKey: self::SECRET, targetBits: 8, minDurationMs: 0);
        $controller = new ChallengeController(
            new Issuer($config, $storage),
            null,
            true,
            $gateway,
            new ContinuityCookie(),
        );
        $marker = new RequestQuarantineMarker($stack);
        $validator = new KiwiCaptchaValidator(
            new Verifier($storage),
            $stack,
            self::SECRET,
            enforceTelemetry: false,
            risk: $gateway,
            // The continuity session feeds the marks identity of the
            // post-solve assessment: without it the submit leg carries
            // no session dimension at all.
            continuityCookie: new ContinuityCookie(),
            dispositionStore: new ArrayPostSolveDispositionStore(),
            quarantineMarker: $marker,
            storage: $storage,
        );
        $dto = new class {
            public ?string $captcha = null;
        };
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $validate = Validation::createValidatorBuilder()
            ->setConstraintValidatorFactory($factory)
            ->getValidator();
        $metadata = $validate->getMetadataFor($dto::class);
        $metadata->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        return [
            'marks' => $store,
            'engine' => $engine,
            'controller' => $controller,
            'stack' => $stack,
            'validate' => $validate,
            'dtoClass' => $dto::class,
            'marker' => $marker,
        ];
    }

    private function markSession(array $harness, string $session): void
    {
        $pseudonym = (new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET)))->sessionId($session);
        $harness['marks']->writeMark('session', $pseudonym, 'spamReported', (int) floor(microtime(true) * 1000));
    }

    /**
     * One challenge leg through the controller: the exact HTTP response
     * the browser would see (status, headers, body) plus its wall time.
     *
     * @return array{status: int, headers: array<string, string>, body: array<string, mixed>, ms: float}
     */
    private function challengeLeg(array $harness, string $session): array
    {
        $request = Request::create(
            '/kiwi-captcha/challenge',
            'POST',
            [],
            [self::SESSION_COOKIE => $session],
            [],
            ['REMOTE_ADDR' => '198.51.100.7', 'CONTENT_TYPE' => 'application/json'],
            '{"scope":"login"}',
        );
        $harness['stack']->push($request);
        $start = hrtime(true);
        try {
            $response = $harness['controller']->challenge($request);
        } finally {
            $harness['stack']->pop();
        }
        $ms = (hrtime(true) - $start) / 1e6;
        $headers = [];
        foreach ($response->headers->allPreserveCase() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        return [
            'status' => $response->getStatusCode(),
            'headers' => $headers,
            'body' => json_decode((string) $response->getContent(), true, 16, JSON_THROW_ON_ERROR),
            'ms' => $ms,
        ];
    }

    /**
     * One submit leg through the full Symfony validation pipeline (the
     * Tier A auto-verify path): validate the solved token, observe the
     * marker.
     *
     * @param array<string, mixed> $challenge
     * @return array{violations: int, held: bool, attribute: bool}
     */
    private function submitLeg(array $harness, string $session, array $challenge, ?string $operationId = null): array
    {
        $token = $this->solve($challenge);
        $request = Request::create(
            '/submit',
            'POST',
            ['captcha' => $token],
            [self::SESSION_COOKIE => $session],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
        );
        if ($operationId !== null) {
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, $operationId);
        }
        $harness['stack']->push($request);
        try {
            $dto = new $harness['dtoClass']();
            $dto->captcha = $token;
            $violations = $harness['validate']->validate($dto);

            return [
                'violations' => count($violations),
                'held' => $harness['marker']->isHeld(),
                'attribute' => $request->attributes->get(QuarantineMarkerInterface::ATTRIBUTE) === true,
            ];
        } finally {
            $harness['stack']->pop();
        }
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function solve(array $challenge): string
    {
        $saltBytes = base64_decode((string) $challenge['salt'], true);
        $prefix = (string) $challenge['prefix'];
        $targetBits = (int) $challenge['targetBits'];
        $counter = 0;
        do {
            $hash = hash('sha256', $prefix.$counter.$saltBytes, true);
            ++$counter;
        } while (Verifier::leadingZeroBits($hash) < $targetBits);
        --$counter;

        return SolutionToken::create((string) $challenge['nonce'], $counter, 5000, [])->encode();
    }

    /**
     * Removes the protocol-varied keys so two challenge bodies compare
     * byte-for-byte on everything the issuance does not randomize.
     *
     * @param array<string, mixed> $body
     */
    private function normalize(array $body): string
    {
        foreach (self::VOLATILE_BODY_KEYS as $key) {
            unset($body[$key]);
        }
        ksort($body);

        return (string) json_encode($body, JSON_UNESCAPED_SLASHES);
    }

    /**
     * A replay of a quarantined operation reproduces the hold from the
     * persisted disposition instead of publishing on the retry.
     *
     * @param array<string, mixed> $reference
     */
    private function replayReproducesTheHold(array $harness, array $reference): void
    {
        $this->markSession($harness, self::MARKED_SESSION);
        $challenge = $this->challengeLeg($harness, self::MARKED_SESSION);
        $this->assertSame($this->normalize($reference), $this->normalize($challenge['body']));
        $token = $this->solve($challenge['body']);
        $operationId = 'wire-diff-replay-1';
        $first = $this->submitLeg($harness, self::MARKED_SESSION, $challenge['body'], $operationId);
        $this->assertSame(0, $first['violations']);
        $this->assertTrue($first['held'], 'the fresh quarantined pass holds');
        $second = $this->submitLeg($harness, self::MARKED_SESSION, $challenge['body'], $operationId);
        $this->assertSame(0, $second['violations'], 'the idempotent retry processes like an allow');
        $this->assertTrue($second['held'], 'the persisted disposition reproduces the hold on the replay');
    }

    /**
     * @param list<float> $deltas
     */
    private function percentile(array $deltas, float $q): float
    {
        sort($deltas);
        if ($deltas === []) {
            return 0.0;
        }
        $index = (int) floor($q * (count($deltas) - 1));

        return $deltas[$index];
    }
}

/**
 * The in-memory risk state store with the long-memory marks surface:
 * the zero vector (a clean identity scores allow) plus mark reads and
 * writes keyed by dimension and identifier.
 */
final class MarksStore implements RiskStateStoreInterface, SessionContextTagStoreInterface, SessionTlsTagStoreInterface, OutcomeMarksStoreInterface
{
    /** @var array<string, array{kind: string, last_kind: string, count: int, first_ms: int, last_ms: int}> */
    public array $marks = [];

    /** @var array<string, string> */
    public array $contextTags = [];

    /** @var array<string, string> */
    public array $tlsTags = [];

    /** @var array<string, true> event-id dedupe markers (marks.lua wire) */
    private array $markEvents = [];

    /** The frozen severity ladder of marks.lua: spam 1 < ban 2 < fraud 3 < chargeback 4. */
    private static function markSeverity(string $kind): int
    {
        return match ($kind) {
            'spamReported' => 1,
            'accountBanned' => 2,
            'fraudConfirmed' => 3,
            'chargeback' => 4,
            default => 0,
        };
    }

    public function observe(RiskObservation $observation): SignalVector
    {
        return SignalVector::zero();
    }

    public function registerOutcome(string $decisionId, int $scope, int $decisionHour, int $score): bool
    {
        return true;
    }

    public function confirmOutcome(string $decisionId, bool $legitimate): int
    {
        return 1;
    }

    public function correctOutcome(string $decisionId, bool $legitimate): bool
    {
        return true;
    }

    public function sessionFirstContextTag(string $sessionId, string $tag): ?string
    {
        return $this->contextTags[$sessionId] ??= $tag;
    }

    public function sessionFirstTlsTag(string $sessionId, string $tag): ?string
    {
        return $this->tlsTags[$sessionId] ??= $tag;
    }

    public function markKey(string $dimension, string $id): string
    {
        return "mark:{kiwi:wire-diff}:{$dimension}:{$id}";
    }

    public function writeMark(string $dimension, string $id, string $kind, int $nowMs, string $eventId = ''): int
    {
        $key = "{$dimension}:{$id}";
        // Event-id idempotency (marks.lua): a retried report with the
        // same id returns the count unchanged.
        if ($eventId !== '') {
            if (isset($this->markEvents[$eventId])) {
                return $this->marks[$key]['count'] ?? 0;
            }
            $this->markEvents[$eventId] = true;
        }
        $existing = $this->marks[$key] ?? null;
        $keptKind = $existing['kind'] ?? $kind;
        if ($existing === null || self::markSeverity($kind) > self::markSeverity($existing['kind'])) {
            $keptKind = $kind;
        }
        $this->marks[$key] = [
            'kind' => $keptKind,
            'last_kind' => $kind,
            'count' => ($existing['count'] ?? 0) + 1,
            'first_ms' => $existing['first_ms'] ?? $nowMs,
            'last_ms' => $nowMs,
        ];

        return $this->marks[$key]['count'];
    }

    public function readMark(string $dimension, string $id): ?array
    {
        return $this->marks["{$dimension}:{$id}"] ?? null;
    }

    public function forgetMarks(string $dimension, string $id): int
    {
        if (!isset($this->marks["{$dimension}:{$id}"])) {
            return 0;
        }
        unset($this->marks["{$dimension}:{$id}"]);

        return 1;
    }
}
