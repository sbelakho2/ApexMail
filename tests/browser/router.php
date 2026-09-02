<?php

declare(strict_types=1);

/**
 * Browser-test fixture server (php -S 127.0.0.1:8085 router.php).
 *
 * Serves the widget page and real challenge/verify endpoints backed by the
 * pure PHP core (no Symfony needed): SHA-256 and Argon2id issuance + local
 * verification, so Playwright can exercise the actual browser solver.
 */

$repo = dirname(__DIR__, 2); // tests/browser -> repo root

require $repo.'/packages/kiwicaptcha-php/vendor/autoload.php';
// The Siteverify e2e route uses the real Symfony bundle
// controller + SiteVerify stores — load the bundle's autoloader when its
// vendor is installed (CI installs it for exactly this fixture fidelity).
$symfonyAutoload = $repo.'/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (is_file($symfonyAutoload)) {
    require $symfonyAutoload;
}

use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;

$secret = '0123456789abcdef0123456789abcdef';
$GLOBALS['kiwi_secret'] = $secret;
// The ExecutionChallengeV1 fixture key (a dedicated key, mirroring the
// bundle's kiwi_captcha.execution_key): armed only under ?execution=1.
$GLOBALS['kiwi_execution_secret'] = 'fedcba9876543210fedcba9876543210';
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// php -S re-includes this router per request, so in-process state is lost —
// the record is persisted to a temp file PER nonce (single-use: consumed
// on verify; a shared file would race when tests issue challenges).
function recordFile(string $nonce): string
{
    return sys_get_temp_dir().'/kiwicaptacha-record-'.preg_replace('/[^A-Za-z0-9_-]/', '', $nonce).'.json';
}
function metadataFile(string $nonce): string
{
    return sys_get_temp_dir().'/kiwicaptacha-meta-'.preg_replace('/[^A-Za-z0-9_-]/', '', $nonce).'.json';
}
// Risk-v2 fixture capture: challenge requests (and form submissions) are
// recorded to a temp file per capture name so Playwright can assert the
// driver's evidence fields (client_context / decoy_field / honeypot /
// chain_ticket) against the real requests the browser sends.
function captureFile(string $name): string
{
    return sys_get_temp_dir().'/kiwicaptacha-capture-'.preg_replace('/[^A-Za-z0-9_-]/', '', $name).'.json';
}
function writeCapture(string $name, string $rawBody): void
{
    if (preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $name) !== 1) {
        return;
    }
    $tmp = tempnam(sys_get_temp_dir(), 'kiwc');
    file_put_contents($tmp, json_encode(['body' => $rawBody, 'at' => time()]));
    rename($tmp, captureFile($name));
}
// ── Chaining fixture (tests/browser/specs/chaining.spec.mjs) ────────────
// The chain state of the chained-challenge fixture: php -S re-includes the
// router per request, so the transactional chain state (chain records +
// obligation mappings) persists in ONE temp file, mirroring the bundle's
// Redis machine (available -> reserved with a short lease -> issued
// (stage2Nonce), then a disposition-aware terminal transition: verified,
// with the obligation cleared atomically, or step_up_required / denied,
// with the obligation mapping kept — a later challenge request for the
// same transaction re-encounters the terminal state, never a new stage-1,
// never a re-reservation). The
// chaining fixture is a file-backed stand-in for the bundle's
// RedisChainedChallengeStateStore — same outcome strings, same strict v2
// record shape.
function chainStateFile(): string
{
    return sys_get_temp_dir().'/kiwicaptacha-chain-state.json';
}

/**
 * The chained-challenge state store of the fixture: the transactional
 * machine persisted to one temp file (the strict v2 schema, the
 * obligation index {obligationId => chainId}, the short owner-scoped
 * lease bounded by the record's own remaining TTL).
 */
final class ChainFileStore implements \BelConsulting\KiwiCaptchaBundle\Risk\TransactionalChainedChallengeStateStore
{
    private const STATES = ['available', 'reserved', 'issued', 'verified', 'step_up_required', 'denied', 'completed'];
    private const CHAINABLE = ['sha16', 'sha18', 'sha20', 'argon16', 'argon32', 'argon64'];

    /** @var array<string, array<string, mixed>> */
    private array $chains = [];
    /** @var array<string, string> */
    private array $obligations = [];

    public function __construct()
    {
        $this->load();
    }

    public function __destruct()
    {
        $this->save();
    }

    private function load(): void
    {
        $file = chainStateFile();
        $raw = is_file($file) ? (string) file_get_contents($file) : '';
        $data = json_decode($raw, true);
        $now = time();
        $this->chains = [];
        $this->obligations = [];
        if (!is_array($data)) {
            return;
        }
        foreach (($data['chains'] ?? []) as $id => $record) {
            if (is_array($record) && isset($record['expiresAt']) && (int) $record['expiresAt'] > $now) {
                $this->chains[(string) $id] = $record;
            }
        }
        foreach (($data['obligations'] ?? []) as $id => $chainId) {
            if (isset($this->chains[(string) $chainId])) {
                $this->obligations[(string) $id] = (string) $chainId;
            }
        }
    }

    private function save(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'kiwc');
        file_put_contents($tmp, json_encode(['chains' => $this->chains, 'obligations' => $this->obligations]));
        rename($tmp, chainStateFile());
    }

    private function live(string $chainId): ?array
    {
        $record = $this->chains[$chainId] ?? null;
        if ($record === null) {
            return null;
        }
        if ((int) $record['expiresAt'] <= time()) {
            unset($this->chains[$chainId]);

            return null;
        }

        return $record;
    }

    private static function record(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $expiresAt): array
    {
        return [
            'v' => 2,
            'stage1Nonce' => $stage1Nonce,
            'scope' => $scope,
            'obligationId' => $obligationId,
            'requiredAction' => $requiredAction,
            'requiredRank' => \KiwiCaptcha\Risk\RiskAction::from($requiredAction)->rank(),
            'policyVersion' => $policyVersion,
            'chainDepth' => 2,
            'state' => 'available',
            'owner' => null,
            'leaseUntil' => null,
            'stage2Nonce' => null,
            'requestBinding' => $requestBinding,
            'expiresAt' => $expiresAt,
        ];
    }

    public function create(string $chainId, string $stage1Nonce, string $scope, int $ttlSecs, ?string $requestBinding = null, ?string $requiredAction = null, int $policyVersion = 1): void
    {
        if ($requiredAction === null || !in_array($requiredAction, self::CHAINABLE, true)) {
            throw new InvalidArgumentException('a chainable requiredAction is required');
        }
        $this->chains[$chainId] = self::record($chainId, hash('sha256', $chainId), $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, time() + max(1, $ttlSecs));
    }

    public function createWithObligation(string $chainId, string $obligationId, string $stage1Nonce, string $scope, ?string $requestBinding, string $requiredAction, int $policyVersion, int $ttlSecs): void
    {
        $this->chains[$chainId] = self::record($chainId, $obligationId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, time() + max(1, $ttlSecs));
        $this->obligations[$obligationId] = $chainId;
    }

    public function createOrGetObligation(string $obligationId, string $chainId, string $stage1Nonce, string $scope, string $requestBinding, string $requiredAction, int $requiredRank, int $policyVersion, int $expiresAt, int $ttlSecs): string
    {
        $existing = $this->obligations[$obligationId] ?? null;
        if ($existing !== null) {
            $record = $this->live($existing);
            if ($record !== null) {
                if ($requiredRank > (int) $record['requiredRank']) {
                    $this->chains[$existing]['requiredRank'] = $requiredRank;
                    $this->chains[$existing]['requiredAction'] = $requiredAction;
                }

                return $existing;
            }
            unset($this->obligations[$obligationId]);
        }
        $this->chains[$chainId] = self::record($chainId, $obligationId, $stage1Nonce, $scope, $requestBinding, $requiredAction, $policyVersion, $expiresAt);
        $this->obligations[$obligationId] = $chainId;

        return $chainId;
    }

    public function obligationChainId(string $obligationId): ?string
    {
        $chainId = $this->obligations[$obligationId] ?? null;
        if ($chainId === null || $this->live($chainId) === null) {
            unset($this->obligations[$obligationId]);

            return null;
        }

        return $chainId;
    }

    public function read(string $chainId): ?array
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return null;
        }
        unset($record['v']);

        return $record;
    }

    public function reserve(string $chainId, string $ownerToken, int $leaseSecs): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        $now = time();
        if ($record['state'] === 'issued') {
            return 'issued';
        }
        if ($record['state'] === 'verified') {
            return 'verified';
        }
        if ($record['state'] === 'completed') {
            return 'completed';
        }
        if ($record['state'] === 'step_up_required') {
            return 'step_up_required';
        }
        if ($record['state'] === 'denied') {
            return 'denied';
        }
        if ($record['state'] === 'reserved') {
            if ($record['owner'] === $ownerToken) {
                return 'retry';
            }
            if ((int) $record['leaseUntil'] > $now) {
                return 'busy';
            }
            $this->chains[$chainId]['owner'] = $ownerToken;
            $this->chains[$chainId]['leaseUntil'] = $now + min(max(1, $leaseSecs), max(1, (int) $record['expiresAt'] - $now));

            return 'taken_over';
        }
        $this->chains[$chainId]['state'] = 'reserved';
        $this->chains[$chainId]['owner'] = $ownerToken;
        $this->chains[$chainId]['leaseUntil'] = $now + min(max(1, $leaseSecs), max(1, (int) $record['expiresAt'] - $now));

        return 'available';
    }

    public function release(string $chainId, string $ownerToken): void
    {
        $record = $this->live($chainId);
        if ($record === null || $record['state'] !== 'reserved' || $record['owner'] !== $ownerToken) {
            return;
        }
        $this->chains[$chainId]['state'] = 'available';
        $this->chains[$chainId]['owner'] = null;
        $this->chains[$chainId]['leaseUntil'] = null;
    }

    public function markIssued(string $chainId, string $ownerToken, string $stage2Nonce): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'reserved') {
            if ($record['owner'] !== $ownerToken) {
                return 'not_owner';
            }
            $this->chains[$chainId]['state'] = 'issued';
            $this->chains[$chainId]['stage2Nonce'] = $stage2Nonce;
            $this->chains[$chainId]['owner'] = null;
            $this->chains[$chainId]['leaseUntil'] = null;

            return 'issued_new';
        }
        if ($record['state'] === 'issued' || $record['state'] === 'completed') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'issued_same' : 'conflict';
        }
        if ($record['state'] === 'verified') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'verified_same' : 'conflict';
        }
        if ($record['state'] === 'step_up_required' || $record['state'] === 'denied') {
            return 'conflict';
        }

        return 'not_owner';
    }

    public function markVerified(string $chainId, string $stage2Nonce): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'verified') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'verified_same' : 'conflict';
        }
        if (($record['state'] !== 'issued' && $record['state'] !== 'completed') || $record['stage2Nonce'] !== $stage2Nonce) {
            return 'conflict';
        }
        $this->chains[$chainId]['state'] = 'verified';
        if (($this->obligations[(string) $record['obligationId']] ?? null) === $chainId) {
            unset($this->obligations[(string) $record['obligationId']]);
        }

        return 'verified_new';
    }

    public function markTransactionDenied(string $chainId, string $obligationId): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        if (($record['obligationId'] ?? null) !== $obligationId) {
            return 'obligation_moved';
        }
        $mapped = $this->obligations[$obligationId] ?? null;
        if ($mapped === null) {
            return 'already_completed';
        }
        if ($mapped !== $chainId) {
            return 'obligation_moved';
        }
        if ($record['state'] === 'denied') {
            return 'denied_same';
        }
        if ($record['state'] === 'verified') {
            return 'already_verified';
        }
        if ($record['state'] === 'step_up_required') {
            return 'conflict';
        }
        if (!in_array($record['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $this->chains[$chainId]['state'] = 'denied';
        $this->chains[$chainId]['owner'] = null;
        $this->chains[$chainId]['leaseUntil'] = null;

        return 'denied_new';
    }

    public function markTransactionStepUpRequired(string $chainId, string $obligationId): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        if (($record['obligationId'] ?? null) !== $obligationId) {
            return 'obligation_moved';
        }
        $mapped = $this->obligations[$obligationId] ?? null;
        if ($mapped === null) {
            return 'already_completed';
        }
        if ($mapped !== $chainId) {
            return 'obligation_moved';
        }
        if ($record['state'] === 'step_up_required') {
            return 'step_up_required_same';
        }
        if ($record['state'] === 'verified') {
            return 'already_verified';
        }
        if ($record['state'] === 'denied') {
            return 'conflict';
        }
        if (!in_array($record['state'], ['available', 'reserved', 'issued', 'completed'], true)) {
            return 'conflict';
        }
        $this->chains[$chainId]['state'] = 'step_up_required';
        $this->chains[$chainId]['owner'] = null;
        $this->chains[$chainId]['leaseUntil'] = null;

        return 'step_up_required_new';
    }

    public function markStepUpRequired(string $chainId, string $stage2Nonce): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'step_up_required') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'step_up_required_same' : 'conflict';
        }
        if ($record['state'] === 'denied') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'conflict' : 'conflict';
        }
        if ($record['state'] !== 'issued' || $record['stage2Nonce'] !== $stage2Nonce) {
            return 'conflict';
        }
        $this->chains[$chainId]['state'] = 'step_up_required';

        return 'step_up_required_new';
    }

    public function markDenied(string $chainId, string $stage2Nonce): string
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return 'missing';
        }
        if ($record['state'] === 'denied') {
            return $record['stage2Nonce'] === $stage2Nonce ? 'denied_same' : 'conflict';
        }
        if ($record['state'] === 'step_up_required') {
            return 'conflict';
        }
        if ($record['state'] !== 'issued' || $record['stage2Nonce'] !== $stage2Nonce) {
            return 'conflict';
        }
        $this->chains[$chainId]['state'] = 'denied';

        return 'denied_new';
    }

    public function rearmIssued(string $chainId, string $expectedStage2Nonce): bool
    {
        $record = $this->live($chainId);
        if ($record === null) {
            return false;
        }
        if (($record['state'] !== 'issued' && $record['state'] !== 'completed') || $record['stage2Nonce'] !== $expectedStage2Nonce) {
            return false;
        }
        $this->chains[$chainId]['state'] = 'available';
        $this->chains[$chainId]['owner'] = null;
        $this->chains[$chainId]['leaseUntil'] = null;
        $this->chains[$chainId]['stage2Nonce'] = null;

        return true;
    }

    public function deleteObligation(string $chainId, string $obligationId): void
    {
        if (($this->obligations[$obligationId] ?? null) === $chainId) {
            unset($this->obligations[$obligationId]);
        }
    }

    public function complete(string $chainId, string $ownerToken, string $stage2Nonce): ?array
    {
        $record = $this->live($chainId);
        if ($record === null || $record['state'] !== 'reserved' || $record['owner'] !== $ownerToken) {
            return null;
        }
        $this->chains[$chainId]['state'] = 'completed';
        $this->chains[$chainId]['stage2Nonce'] = $stage2Nonce;
        $this->chains[$chainId]['owner'] = null;
        $this->chains[$chainId]['leaseUntil'] = null;

        return $this->read($chainId);
    }
}

/**
 * The fixture's authoritative transaction-binding resolver: the
 * authoritative binding of a transaction IS the container's
 * data-kiwi-request-binding value (the server-attested transaction id the
 * fixture derives from the request itself — the same value at stage-1 and
 * stage-2). A malformed value is refused; null = unbound.
 */
final class FixtureBindingAuthority implements \BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface
{
    public function resolve(?\Symfony\Component\HttpFoundation\Request $request, string $scope, ?string $presentedBinding): ?string
    {
        if ($presentedBinding === null || $presentedBinding === '') {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $presentedBinding) !== 1) {
            throw new \InvalidArgumentException('malformed presented binding');
        }

        return $presentedBinding;
    }
}

/**
 * Rebuild the exact issuance response of an already-issued challenge from
 * its stored record (the bundle controller's rebuildIssuanceResponse
 * mapping — the response shape is camelCase, the record shape snake_case).
 */
function rebuildChallengeResponse(array $recordData): array
{
    $response = [
        'nonce' => $recordData['nonce'],
        'challenge' => $recordData['challenge'],
        'salt' => $recordData['salt'],
        'algorithm' => $recordData['algorithm'],
        'mKib' => $recordData['m_kib'],
        't' => $recordData['t'],
        'p' => $recordData['p'],
        'targetBits' => $recordData['target_bits'],
        'ttlSecs' => $recordData['expires_at'] - $recordData['issued_at'],
        'minDurationMs' => $recordData['min_duration_ms'],
        'prefix' => $recordData['prefix'],
    ];
    // The canonical issuance-response key set of the bundle controller
    // (issuanceResponseFromRecord): the authenticated decoy field and
    // the execution program ride the response exactly when the stored
    // record carries them, so a recovered stage-2 response is
    // byte-identical with the original handoff (execution_version and
    // execution_commitment never appear on the client-facing surface).
    if (isset($recordData['decoy_field']) && $recordData['decoy_field'] !== null) {
        $response['decoy_field'] = $recordData['decoy_field'];
    }
    if (isset($recordData['execution_program']) && $recordData['execution_program'] !== null) {
        $response['execution_program'] = $recordData['execution_program'];
    }

    return $response;
}

/**
 * The chained /challenge handler (mirror of the bundle controller's
 * stage-2 gate) validates the presented ticket against the current
 * transaction's obligation; a foreign ticket gets 422. It auto-resumes an
 * open chain when no ticket is presented, recovers/rearms the issued
 * stage-2 challenge, claims the short owner-scoped reservation and mints
 * the stronger argon stage (markIssued idempotent). A chain in the
 * terminal step_up_required/denied state answers its terminal response
 * directly — 403 step_up_required / 429 risk_denied — before any
 * reservation attempt (never a new challenge, never a stage-1, never a
 * re-reservation). Returns [status, body] or null when the request is an
 * ordinary stage-1 flow.
 */
function chainedChallenge(array $body, string $scope, ?string $ticket): ?array
{
    if (($body['chain_ticket'] ?? null) === null && $ticket === null) {
        $ticket = null;
    }
    $chainStore = new ChainFileStore();
    $authority = new FixtureBindingAuthority();
    $chainService = new \BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService($chainStore, $GLOBALS['kiwi_secret'], 300, 15, $authority);
    $presented = isset($body['request_binding']) && is_string($body['request_binding']) ? $body['request_binding'] : null;
    try {
        $binding = $authority->resolve(null, $scope, $presented);
    } catch (\InvalidArgumentException) {
        return [422, ['error' => ['code' => 'INVALID_REQUEST_BINDING', 'message' => 'The request binding does not match this transaction.']]];
    }
    $requirement = null;
    try {
        $requirement = $chainService->findOpenRequirement($scope, $binding ?? '', 1);
    } catch (\Throwable) {
        return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
    }

    $chainId = null;
    if (is_string($ticket) && $ticket !== '') {
        $payload = $chainService->verify($ticket);
        if ($payload === null) {
            return [422, ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid or expired.']]];
        }
        if ($requirement === null || $requirement->chainId !== (string) $payload['chainId']) {
            $direct = null;
            try {
                $direct = $chainService->requirementFor((string) $payload['chainId']);
            } catch (\Throwable) {
                return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
            }
            if ($direct === null || $direct->scope !== $scope || $direct->requestBinding !== ($binding ?? '')) {
                return [422, ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket does not match this transaction.']]];
            }
            $requirement = $direct;
        }
        $chainId = (string) $payload['chainId'];
    } elseif ($requirement !== null) {
        // auto-resume: no ticket, open obligation -> stage 2.
        $chainId = $requirement->chainId;
    }

    if ($chainId === null) {
        return null; // ordinary stage-1 flow
    }

    // stage-2 state entry: recover / rearm / reserve.
    $owner = bin2hex(random_bytes(16));
    for ($i = 0; $i < 3; $i++) {
        if ($requirement->state === 'verified') {
            $recovered = recoverIssuedResponse((string) $requirement->stage2Nonce);
            if ($recovered !== null) {
                return [200, $recovered];
            }

            return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
        }
        if ($requirement->state === 'issued') {
            $inspection = inspectIssuedStage2($chainId, (string) $requirement->stage2Nonce, $chainService);
            if ($inspection !== null) {
                return $inspection;
            }
        }
        if ($requirement->state === 'step_up_required') {
            // terminal step-up: the transaction is bound to its final
            // step-up disposition (the obligation mapping was kept) — no
            // challenge issuance, ever. A later request for the same
            // transaction re-encounters this terminal state.
            return [403, ['error' => ['code' => 'STEP_UP_REQUIRED', 'message' => 'Additional verification is required for this request.']]];
        }
        if ($requirement->state === 'denied') {
            // terminal denial: the transaction is bound to its final
            // denial disposition (the obligation mapping was kept) — no
            // challenge issuance, ever. A later request for the same
            // transaction re-encounters this terminal state.
            return [429, ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']]];
        }
        $reservation = $chainService->reserveStage2($chainId, $owner);
        if ($reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Available
            || $reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::TakenOver
            || $reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Retry
        ) {
            break;
        }
        if ($reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Busy) {
            return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'A challenge for this chain ticket is already in progress. Try again later.']]];
        }
        if ($reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Issued
            || $reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Verified
            || $reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::StepUpRequired
            || $reservation === \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Denied
        ) {
            try {
                $requirement = $chainService->requirementFor($chainId);
            } catch (\Throwable) {
                return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
            }
            if ($requirement === null) {
                return [422, ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid, expired or already consumed.']]];
            }
            continue;
        }

        return [422, ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid, expired or already consumed.']]];
    }

    // mint THE stronger stage-2 (argon) + idempotent markIssued.
    $stage2 = mintChallenge($scope, $binding, PoWAlgorithm::Argon2id);
    if ($stage2 === null) {
        return [500, ['error' => 'mint failed']];
    }
    $issued = $chainService->markIssued($chainId, $owner, $stage2['nonce']);
    if (!in_array($issued, [\BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedNew, \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedSame, \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::VerifiedSame], true)) {
        return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
    }

    return [200, $stage2];
}

/**
 * The issued-stage-2 inspection of the fixture: a pending record recovers
 * the exact same challenge; a missing record rearms for a fresh stage-2
 * mint (never a stage-1). It returns [status, body] or null when the
 * chain was rearmed; the caller then proceeds to the reservation + mint.
 */
function inspectIssuedStage2(string $chainId, string $stage2Nonce, \BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService $chainService): ?array
{
    $record = challengeRecordOf($stage2Nonce);
    if ($record === null) {
        try {
            $rearmed = $chainService->rearmIssued($chainId, $stage2Nonce);
        } catch (\Throwable) {
            return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
        }
        if (!$rearmed) {
            return [503, ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable.']]];
        }

        return null;
    }

    return [200, rebuildChallengeResponse($record)];
}

/** The persisted record of a nonce (the record file), or null. */
function challengeRecordOf(string $nonce): ?array
{
    $file = recordFile($nonce);
    if (!is_file($file)) {
        return null;
    }
    $raw = json_decode((string) file_get_contents($file), true);
    if (!is_array($raw)) {
        return null;
    }

    return $raw;
}

/** The recovered issuance response of an issued challenge, or null. */
function recoverIssuedResponse(string $stage2Nonce): ?array
{
    $record = challengeRecordOf($stage2Nonce);
    if ($record === null) {
        return null;
    }

    return rebuildChallengeResponse($record);
}

/**
 * Mint a challenge (sha256-8 stage-1 or the stronger argon stage-2) and
 * persist its record file, mirroring the bundle's /challenge issuance.
 * With $armDecoy the issuance goes through the real authenticated
 * decoy path (issueWithDecoyField: protocol-v3 record, the decoy name
 * signed into the canonical payload), the mirror of the bundle's
 * risk.decoy_v3_enabled issuance. $pinnedDecoy (fixture-only) pins the
 * armed name so a spec can force a deliberate collision with an
 * application field; the pinned name is signed into the record exactly
 * like any other armed name.
 *
 * $shaBits / $argonBits / $argonMKib are opt-in difficulty
 * overrides (the client-performance lab's ?bits= / ?argon_bits= /
 * ?m_kib= knobs). The defaults reproduce the historical fixture
 * byte-for-byte, and every value is clamped to the same ceilings the
 * core enforces, so a malformed override falls back to the default
 * instead of crashing the fixture.
 */
function mintChallenge(string $scope, ?string $binding, PoWAlgorithm $algorithm, bool $armDecoy = false, ?int $ttlOverride = null, ?string $pinnedDecoy = null, int $shaBits = 8, int $argonBits = 4, int $argonMKib = 64, bool $armExecution = false, ?string $executionAction = null, int $executionVersion = 1): ?array
{
    $shaBits = min(max($shaBits, 1), Config::MAX_SHA_TARGET_BITS);
    $argonBits = min(max($argonBits, 1), Config::MAX_ARGON2_TARGET_BITS);
    $argonMKib = min(max($argonMKib, 8), 65536);
    $config = new Config(
        secretKey: $GLOBALS['kiwi_secret'],
        algorithm: $algorithm,
        ttlSecs: $ttlOverride ?? 120,
        mKib: $algorithm === PoWAlgorithm::Argon2id ? $argonMKib : 0,
        t: $algorithm === PoWAlgorithm::Argon2id ? 3 : 1,
        p: 1,
        targetBits: $shaBits,
        argon2TargetBits: $argonBits,
        minDurationMs: 0,
        // The ExecutionChallengeV1 keyed-PRF key: the fixture uses a
        // dedicated key (the mirror of kiwi_captcha.execution_key), so
        // the execution dimension is armed only under ?execution=1 and
        // never by accident.
        executionKey: $GLOBALS['kiwi_execution_secret'],
    );
    $storage = new ArrayStorage();
    $issuer = new Issuer($config, $storage, now: static fn (): int => time());
    if ($armExecution) {
        // The armed issuance path: program generated from the challenge
        // context (nonce/scope/action/version), stamped on the record
        // AND the response; the driver runs it and presents the digest.
        // $executionVersion is the grammar version selected by the
        // /challenge handler (the mirror of the bundle controller's
        // effectiveExecutionVersion rule); see the handler comment.
        $challenge = $issuer->issueWithExecutionField($scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), true, $binding, null, $executionAction ?? 'default', $executionVersion, $armDecoy, $pinnedDecoy);
    } else {
        $challenge = $armDecoy
            ? $issuer->issueWithDecoyField($scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), true, $binding, null, $pinnedDecoy)
            : $issuer->issue($scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), $binding);
    }
    $record = $storage->find($challenge->nonce);
    if ($record === null) {
        return null;
    }
    $tmp = tempnam(sys_get_temp_dir(), 'kiw');
    file_put_contents($tmp, json_encode($record->toArray()));
    rename($tmp, recordFile($challenge->nonce));

    return $challenge->toArray();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/chain-verify') {
    // The chaining form-submission fixture: verifies a solved token and
    // resolves the transaction disposition — a stage-1 solve opens the
    // chain (chain_required + the one-shot ticket), a stage-2 solve (with
    // the ticket) verifies the chain (the obligation is cleared).
    $body = json_decode((string) file_get_contents('php://input'), true);
    header('Content-Type: application/json');
    $token = is_array($body) && isset($body['token']) && is_string($body['token']) ? $body['token'] : '';
    $chainTicket = is_array($body) && isset($body['chain_ticket']) && is_string($body['chain_ticket']) ? $body['chain_ticket'] : null;
    $scope = is_array($body) && isset($body['scope']) && is_string($body['scope']) ? $body['scope'] : 'login';
    $binding = is_array($body) && isset($body['request_binding']) && is_string($body['request_binding']) ? $body['request_binding'] : null;
    $nonce = (string) (explode('.', (string) base64_decode($token, true))[0] ?? '');
    if ($nonce === '' || !is_file(recordFile($nonce))) {
        echo json_encode(['ok' => false, 'code' => 'record_not_found']);

        return true;
    }
    $storage = new ArrayStorage();
    $storage->store(\KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($nonce)), true)));
    // The exact-binding contract: the challenge was minted bound to the
    // transaction ($binding, carried in the form body); the redemption
    // must present it (the exact default refuses a bound challenge
    // without its binding).
    $outcome = (new Verifier($storage))->verify($token, $GLOBALS['kiwi_secret'], $scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), expectedRequestBinding: $binding);
    if (!$outcome->isOk()) {
        echo json_encode(['ok' => false, 'code' => $outcome->code()]);

        return true;
    }
    $chainStore = new ChainFileStore();
    $chainService = new \BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService($chainStore, $GLOBALS['kiwi_secret'], 300, 15, new FixtureBindingAuthority());
    $disposition = is_array($body) && isset($body['disposition']) && is_string($body['disposition']) ? $body['disposition'] : null;
    if ($disposition === 'deny' || $disposition === 'step_up') {
        // THE terminalization knob of the fixture (the mirror of the
        // validator's post-solve dispositions): a fresh Deny/StepUp of a
        // verified nonce of the obligated transaction terminalizes the
        // open obligation durably (nonce-agnostic — the obligation
        // mapping is kept, so a later challenge request re-encounters the
        // terminal state, never a new stage-1).
        $requirement = $chainService->findOpenRequirement($scope, $binding ?? '', 1);
        if ($requirement === null) {
            echo json_encode(['ok' => false, 'code' => 'no_open_chain']);

            return true;
        }
        $obligationId = $chainService->obligationIdFor($scope, $binding ?? '', 1);
        $terminal = $disposition === 'deny'
            ? $chainService->markTransactionDenied($requirement->chainId, $obligationId)
            : $chainService->markTransactionStepUpRequired($requirement->chainId, $obligationId);
        if (!in_array($terminal, [
            \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::DeniedNew,
            \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::DeniedSame,
            \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::StepUpRequiredNew,
            \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::StepUpRequiredSame,
        ], true)) {
            echo json_encode(['ok' => false, 'code' => 'chain_terminalization_refused']);

            return true;
        }
        echo json_encode(['ok' => false, 'code' => $disposition === 'deny' ? 'RISK_DENIED' : 'STEP_UP_REQUIRED']);

        return true;
    }
    if (is_string($chainTicket) && $chainTicket !== '') {
        // stage-2 solve: the chain is marked verified (the obligation is
        // cleared atomically) and the consumed record is retired.
        $payload = $chainService->verify($chainTicket);
        if ($payload === null) {
            echo json_encode(['ok' => false, 'code' => 'invalid_ticket']);

            return true;
        }
        $requirement = $chainService->findOpenRequirement($scope, $binding ?? '', 1);
        if ($requirement === null || $requirement->chainId !== (string) $payload['chainId']) {
            echo json_encode(['ok' => false, 'code' => 'ticket_mismatch']);

            return true;
        }
        $verified = $chainService->markVerified((string) $payload['chainId'], $nonce);
        if (!in_array($verified, [\BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::VerifiedNew, \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::VerifiedSame], true)) {
            echo json_encode(['ok' => false, 'code' => 'chain_verification_refused']);

            return true;
        }
        @unlink(recordFile($nonce));
        echo json_encode(['ok' => true, 'chain_ended' => true]);

        return true;
    }
    // stage-1 solve: the reassessment demands the stronger argon stage —
    // the chain opens (one obligation per transaction). The ticket is
    // signed from the server-held requirement's actual expiry — never a
    // second clock read that could straddle the chain's expiry boundary.
    $requirement = $chainService->requireStage2($nonce, $scope, $binding ?? '', 1, \KiwiCaptcha\Risk\RiskAction::Argon32, time() + 300);
    $ticket = $chainService->ticketFor($requirement->chainId, $requirement->expiresAt);
    echo json_encode(['ok' => false, 'chain_required' => true, 'chain_ticket' => $ticket]);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && $path === '/chain-store-selftest') {
    // The fixture store's state-machine self-test (asserted by the
    // chaining spec): pins the production terminal semantics at the store
    // level — reserve() answers the terminal statuses (a terminal chain
    // can never be set back to reserved) and markIssued() answers
    // 'conflict' on a terminal chain — mirroring the bundle's Lua.
    header('Content-Type: application/json');
    $failures = [];
    $check = static function (string $name, bool $ok) use (&$failures): void {
        if (!$ok) {
            $failures[] = $name;
        }
    };
    try {
        $store = new ChainFileStore();
        $base = 'selftest-'.bin2hex(random_bytes(6));
        $nonceA = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
        $nonceB = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
        $deniedChain = $base.'-denied';
        $deniedObligation = hash('sha256', $deniedChain);
        $store->createWithObligation($deniedChain, $deniedObligation, $nonceA, 'login', 'txn-selftest-denied', 'argon32', 1, 120);
        $check('denied: fresh reserve', $store->reserve($deniedChain, 'owner-a', 15) === 'available');
        $check('denied: markIssued', $store->markIssued($deniedChain, 'owner-a', $nonceB) === 'issued_new');
        $check('denied: terminalize', $store->markTransactionDenied($deniedChain, $deniedObligation) === 'denied_new');
        $check('denied: reserve answers denied', $store->reserve($deniedChain, 'owner-b', 15) === 'denied');
        $check('denied: never re-reserved', $store->read($deniedChain)['state'] === 'denied');
        $check('denied: markIssued conflict', $store->markIssued($deniedChain, 'owner-b', $nonceB) === 'conflict');
        $check('denied: cannot flip to step-up', $store->markTransactionStepUpRequired($deniedChain, $deniedObligation) === 'conflict');
        $otherChain = $base.'-other';
        $otherObligation = hash('sha256', $otherChain);
        $store->createWithObligation($otherChain, $otherObligation, $nonceA, 'login', 'txn-selftest-other', 'argon32', 1, 120);
        $check('denied: moved obligation refused', $store->markTransactionDenied($deniedChain, $otherObligation) === 'obligation_moved');
        $check('denied: unknown obligation id is obligation-moved', $store->markTransactionDenied($deniedChain, hash('sha256', 'never-registered')) === 'obligation_moved');
        $completedChain = $base.'-completed';
        $completedObligation = hash('sha256', $completedChain);
        $store->createWithObligation($completedChain, $completedObligation, $nonceA, 'login', 'txn-selftest-completed', 'argon32', 1, 120);
        $store->deleteObligation($completedChain, $completedObligation);
        $check('denied: correct id with deleted mapping is already-completed', $store->markTransactionDenied($completedChain, $completedObligation) === 'already_completed');
        $stepUpChain = $base.'-stepup';
        $stepUpObligation = hash('sha256', $stepUpChain);
        $store->createWithObligation($stepUpChain, $stepUpObligation, $nonceA, 'login', 'txn-selftest-stepup', 'argon32', 1, 120);
        $check('step_up: terminalize', $store->markTransactionStepUpRequired($stepUpChain, $stepUpObligation) === 'step_up_required_new');
        $check('step_up: reserve answers step_up_required', $store->reserve($stepUpChain, 'owner-b', 15) === 'step_up_required');
        $check('step_up: never re-reserved', $store->read($stepUpChain)['state'] === 'step_up_required');
        $check('step_up: markIssued conflict', $store->markIssued($stepUpChain, 'owner-b', $nonceB) === 'conflict');
    } catch (\Throwable $e) {
        $failures[] = 'exception: '.$e->getMessage();
    }
    echo json_encode(['ok' => $failures === [], 'failures' => $failures]);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && preg_match('~^/capture/([A-Za-z0-9_-]{1,64})$~', $path, $m) === 1) {
    header('Content-Type: application/json');
    $f = captureFile($m[1]);
    echo json_encode(is_file($f) ? json_decode((string) file_get_contents($f), true) : null);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/form-submit') {
    // The form-submission honeypot fixture endpoint: records the raw POST
    // body exactly as the browser sent it (the decoy field rides the
    // form's application/x-www-form-urlencoded payload).
    writeCapture('form', http_build_query($_POST));
    header('Content-Type: application/json');
    echo json_encode(['ok' => true]);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($path === '/challenge' || $path === '/kiwi-captcha/challenge')) {
    $rawBody = (string) file_get_contents('php://input');
    // Risk-v2 fixture capture: ?capture=<name> records the raw challenge
    // request body for the Playwright assertions.
    if (isset($_GET['capture']) && is_string($_GET['capture'])) {
        writeCapture($_GET['capture'], $rawBody);
    }
    $body = json_decode($rawBody, true);
    // ?escalate=argon mirrors the adaptive risk escalation: the server
    // issues a memory-hard challenge even though the widget asked for the
    // SHA-256 profile (the driver accepts the stronger algorithm and
    // lazily fetches the WASM runtime in files mode).
    $escalated = ($_GET['escalate'] ?? '') === 'argon';
    $requestedArgon = ($body['algorithm'] ?? 'sha256') === 'argon2id';
    $algorithm = $escalated || $requestedArgon ? PoWAlgorithm::Argon2id : PoWAlgorithm::Sha256;
    $ttlOverride = isset($_GET['ttl']) ? max(1, (int) $_GET['ttl']) : null;
    // The bundle maps incumbent sitekeys -> policy scopes server-side
    // (sitekey_allowlist); the fixture mirrors that mapping so compat
    // challenges are issued under the intended scope.
    $sitekeyAllowlist = [
        '6Lc_turnstile_meta' => 'login',
        '0x4AAAAAAABC' => 'login',
        '6Lc_turnstile' => 'login',
        '6Lc_dynamic_explicit' => 'login',
        '6Lc_dynamic_implicit' => 'login',
        '6Lc_explicit_checkout_login' => 'login',
        '6Lc_explicit_login' => 'login',
        '6Lc_ready_explicit' => 'login',
    ];
    $scope = $sitekeyAllowlist[(string) ($body['scope'] ?? '')] ?? (string) ($body['scope'] ?? 'login');
    // The fixture mirrors the bundle's server-owned
    // (sitekey, action) -> scope policy — the v3 browser e2e proves the
    // pair travels separately and resolves server-side.
    $sitekeyPolicy = [
        '6Lc_v3_sitekey_a' => ['default_scope' => 'login', 'actions' => ['checkout' => 'commerce_high_value']],
    ];
    $sitekey = isset($body['sitekey']) && is_string($body['sitekey']) ? $body['sitekey'] : null;
    if ($sitekey !== null && isset($sitekeyPolicy[$sitekey])) {
        $actionKey = isset($body['action']) && is_string($body['action']) ? $body['action'] : '';
        if ($actionKey !== '' && isset($sitekeyPolicy[$sitekey]['actions'][$actionKey])) {
            $scope = $sitekeyPolicy[$sitekey]['actions'][$actionKey];
        } elseif ($actionKey === '') {
            $scope = $sitekeyPolicy[$sitekey]['default_scope'];
        } else {
            http_response_code(422);
            echo '{"error":{"code":"UNKNOWN_ACTION"}}';

            return true;
        }
    }
    // chaining fixture (?chaining=1): the transaction-obligation stage-2
    // gate — a presented chain_ticket must match the current
    // transaction's obligation (a foreign ticket -> 422), an open
    // obligation auto-resumes the chain without a ticket (never issue
    // stage 1), the issued stage-2 challenge is recovered/rearmed, and
    // the stronger argon stage is minted + durably issued (markIssued).
    // Without ?chaining=1 the ticket is ignored (a deployment without
    // risk.chaining — the risk-v2 evidence specs rely on that).
    $chainTicket = isset($body['chain_ticket']) && is_string($body['chain_ticket']) ? $body['chain_ticket'] : null;
    if (($_GET['chaining'] ?? '') === '1') {
        $chained = chainedChallenge($body, $scope, $chainTicket);
        if ($chained !== null) {
            http_response_code($chained[0]);
            header('Cache-Control: no-store, private, max-age=0');
            echo json_encode($chained[1]);

            return true;
        }
    }
    // The fixture mirrors the production binding contract: the stage-1
    // challenge is minted bound to the presented transaction binding
    // (the same value the chain machinery opens the obligation under), so
    // the browser E2E can prove that a proof minted under txn-A fails
    // when redeemed under txn-B — the stored proof really carries the
    // binding, exactly like the bundle's issuance.
    $presentedBinding = isset($body['request_binding']) && is_string($body['request_binding']) ? $body['request_binding'] : null;
    // ?decoy=pool&decoyname=<name> pins the authenticated armed name (the
    // fixture-only issuer seam signs the pinned name into the record), so
    // a spec can force a deliberate collision with an application field.
    $pinnedDecoy = (string) ($_GET['decoyname'] ?? '');
    $pinnedDecoy = $pinnedDecoy !== '' && preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $pinnedDecoy) === 1 ? $pinnedDecoy : null;
    // Client-performance-lab difficulty knobs (opt-in; the defaults
    // reproduce the historical fixture): ?bits=<1..20> overrides the
    // SHA-256 target bits, ?argon_bits=<1..10> and ?m_kib=<8..65536>
    // override the Argon2id target bits and memory envelope. Malformed
    // values fall back to the defaults inside mintChallenge.
    $shaBits = ctype_digit((string) ($_GET['bits'] ?? '')) ? (int) $_GET['bits'] : 8;
    $argonBits = ctype_digit((string) ($_GET['argon_bits'] ?? '')) ? (int) $_GET['argon_bits'] : 4;
    $argonMKib = ctype_digit((string) ($_GET['m_kib'] ?? '')) ? (int) $_GET['m_kib'] : 64;
    // The ExecutionChallengeV1 fixture seam (?execution=1): the mirror
    // of the bundle's risk.execution_challenge gate — the challenge
    // response carries an execution program the driver must run (the
    // digest rides the solution token; the fixture's /verify recomputes
    // the expected digest from the stored program).
    $armExecution = ($_GET['execution'] ?? '') === '1';
    $executionAction = isset($body['action']) && is_string($body['action']) ? $body['action'] : null;
    // Execution version selection, the mirror of the bundle controller's
    // effectiveExecutionVersion rule. The fixture simulates a current
    // deployment of the v2-capable generation, so it assumes its own
    // execution-version cap and the central fleet floor are confirmed
    // at 2: ?execution=1 stands in for the whole execution rollout
    // state, and no SecurityEpochMonitor or {kiwi:<ns>}:security-policy
    // hash is wired in the fixture. The effective grammar version is
    // therefore 2 exactly when the client advertised
    // execution_max_version >= 2 with the challenge request; the
    // current driver sends 2 when the execution tier is configured.
    // Any other value issues version 1, since an older driver never
    // sends the field, exactly like the N-1 knob below.
    // ?execution_max_version=<1|2> on the endpoint overrides the
    // advertised capability: the fixture lever standing in for a stale
    // page whose driver never advertises. The GET override wins over
    // the body claim, since the server reads the capability the client
    // presents, and the knob simulates what that client presents.
    $executionMaxVersion = 1;
    $capability = $body['execution_max_version'] ?? null;
    if (is_int($capability)) {
        $executionMaxVersion = $capability >= 2 ? 2 : 1;
    } elseif (is_string($capability) && ctype_digit($capability)) {
        $executionMaxVersion = (int) $capability >= 2 ? 2 : 1;
    }
    $getCapability = (string) ($_GET['execution_max_version'] ?? '');
    if (ctype_digit($getCapability)) {
        $executionMaxVersion = (int) $getCapability >= 2 ? 2 : 1;
    }
    $challenge = mintChallenge($scope, $presentedBinding, $algorithm, ($_GET['decoy'] ?? '') === 'pool', $ttlOverride, $pinnedDecoy, $shaBits, $argonBits, $argonMKib, $armExecution, $executionAction, $executionMaxVersion);
    if ($challenge === null) {
        http_response_code(500);
        echo '{"error":"record missing"}';

        return true;
    }
    // Provider-compatible metadata bound at issuance —
    // action/cData from the widget's challenge request are stored against
    // the nonce (server-owned; validated provider shapes).
    $action = isset($body['action']) && is_string($body['action']) ? $body['action'] : null;
    $cdata = isset($body['cdata']) && is_string($body['cdata']) ? $body['cdata'] : null;
    if ($action !== null || $cdata !== null) {
        if ($action !== null && !preg_match('/^[a-z0-9_-]{1,32}$/i', $action)) {
            http_response_code(422);
            echo '{"error":{"code":"INVALID_METADATA"}}';

            return true;
        }
        if ($cdata !== null && !preg_match('/^[a-z0-9_-]{1,255}$/i', $cdata)) {
            http_response_code(422);
            echo '{"error":{"code":"INVALID_METADATA"}}';

            return true;
        }
        $metaTmp = tempnam(sys_get_temp_dir(), 'kiwm');
        file_put_contents($metaTmp, json_encode(['action' => $action, 'cdata' => $cdata]));
        rename($metaTmp, metadataFile($challenge['nonce']));
    }
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    $out = $challenge;
    // Risk-v2 fixture: ?decoy=1 makes the fixture emit the server-issued
    // decoy (honeypot) field name, mirroring the bundle's risk-enabled
    // issuance response. The name is a grammar prefix (deterministic per
    // nonce) plus a fresh random suffix — the response-only surface, the
    // record itself is unarmed; ?decoyname=... overrides the emitted name
    // with a fixed one, so specs can pin the exact name (for ?decoy=pool
    // it pins the authenticated armed name too, see mintChallenge).
    if (($_GET['decoy'] ?? '') === '1') {
        $override = (string) ($_GET['decoyname'] ?? '');
        if ($override !== '' && preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $override) === 1) {
            $out['decoy_field'] = $override;
        } else {
            $h = hash('sha256', $challenge['nonce']);
            $out['decoy_field'] = Issuer::composeDecoyName(
                hexdec(substr($h, 0, 2)) % \count(Issuer::DECOY_GRAMMAR_SLOT1_QUALIFIER),
                hexdec(substr($h, 2, 2)) % \count(Issuer::DECOY_GRAMMAR_SLOT2_CATEGORY),
                hexdec(substr($h, 4, 2)) % \count(Issuer::DECOY_GRAMMAR_SLOT3_FORM),
            );
        }
    }
    // ?strategy=N emits the non-authenticated rendering-strategy hint
    // (0-5) the widget driver honors when present, so the three-engine
    // lane can force every polymorphic variant deterministically.
    // Production responses omit it.
    if (($_GET['strategy'] ?? '') !== '' && ctype_digit((string) $_GET['strategy'])) {
        $strategy = (int) $_GET['strategy'];
        if ($strategy >= 0 && $strategy <= 5) {
            $out['strategy'] = $strategy;
        }
    }
    echo json_encode($out);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($path === '/siteverify' || $path === '/kiwi-captcha/siteverify')) {
    // e2e: the real SiteVerifyController against the record
    // + metadata persisted at issuance (the fixture's file-based storage
    // stands in for the shared store). The wire body may arrive as JSON
    // or as the raw application/x-www-form-urlencoded form (the provider
    // contract): both are parsed here.
    $rawBody = (string) file_get_contents('php://input');
    $body = json_decode($rawBody, true);
    if (!is_array($body)) {
        parse_str($rawBody, $body);
    }
    // Pre-decode diagnostic (fixture-only, hashes and lengths only,
    // never token bytes): a failing Turnstile request that never reaches
    // the core verifier (the provider response is invalid-input-response
    // from the token decode) cannot be explained by the observer. Log
    // the submitted response's length and sha256 plus the exact
    // SolutionToken decode result, so a browser-token translation break
    // is localizable in one line.
    $preDecodeToken = (string) ($body['response'] ?? '');
    $preDecode = null;
    try {
        $preDecodeToken = (string) SolutionToken::decode($preDecodeToken)->nonce;
        $preDecode = 'ok';
    } catch (\Throwable $e) {
        $preDecode = get_class($e);
    }
    $GLOBALS['kiwi_last_siteverify_predecode'] = [
        'response_len' => \strlen((string) ($body['response'] ?? '')),
        'response_sha256' => hash('sha256', (string) ($body['response'] ?? '')),
        'decode' => $preDecode,
        'content_type' => (string) ($_SERVER['CONTENT_TYPE'] ?? ''),
        'raw_len' => \strlen($rawBody),
        // The controller sees the rebuilt form body, not the original
        // JSON: the rebuilt token must be byte-identical to the original
        // or the decode/verify below operate on a mangled value.
        'rebuilt_token_sha256' => null,
        // The token's character profile: base64url characters plus the
        // standard-alphabet '+'/'/' and '=' padding are the only wire
        // encoding-sensitive characters in a token.
        'token_plus' => substr_count((string) ($body['response'] ?? ''), '+'),
        'token_slash' => substr_count((string) ($body['response'] ?? ''), '/'),
        'token_eq' => substr_count((string) ($body['response'] ?? ''), '='),
        'token_underscore' => substr_count((string) ($body['response'] ?? ''), '_'),
        'token_dash' => substr_count((string) ($body['response'] ?? ''), '-'),
    ];
    // Fixture-only probe: re-verify the token against a copy of the
    // persisted record with the same configuration the controller uses
    // (secret, scope 'login' from the siteverify map, remoteip), so a
    // pre-verification controller rejection is distinguishable from a
    // genuine verification failure. The probe consumes its own copy,
    // never the persisted record file.
    $GLOBALS['kiwi_last_siteverify_probe'] = null;
    $probeNonce = (string) (explode('.', (string) base64_decode((string) ($body['response'] ?? ''), true))[0] ?? '');
    if ($probeNonce !== '' && is_file(recordFile($probeNonce))) {
        try {
            $probeRecord = \KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($probeNonce)), true));
            $probeStorage = new ArrayStorage();
            $probeStorage->store($probeRecord);
            $probeOutcome = (new Verifier($probeStorage))->verify(
                (string) ($body['response'] ?? ''),
                $GLOBALS['kiwi_secret'],
                'login',
                (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'),
            );
            $GLOBALS['kiwi_last_siteverify_probe'] = $probeOutcome->code();
        } catch (\Throwable $e) {
            $GLOBALS['kiwi_last_siteverify_probe'] = 'probe-exception:'.get_class($e);
        }
    }
    header('Content-Type: application/json');
    header('Cache-Control: no-store, private, max-age=0');
    $nonce = (string) (explode('.', (string) base64_decode((string) ($body['response'] ?? ''), true))[0] ?? '');
    if ($nonce === '' || !is_file(recordFile($nonce))) {
        echo json_encode(['success' => false, 'error-codes' => ['timeout-or-duplicate']]);

        return true;
    }
    $storage = new ArrayStorage();
    $storage->store(\KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($nonce)), true)));
    $metadataStore = new \BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore();
    if (is_file(metadataFile($nonce))) {
        $m = json_decode((string) file_get_contents(metadataFile($nonce)), true);
        $metadataStore->store($nonce, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata($m['action'] ?? null, $m['cdata'] ?? null, null), 300);
        // The metadata file is preserved until the logical transaction is
        // actually consumed (a failed verification must not lose the
        // persisted action/cdata — the production retained-state model).
    }
    $controller = new \BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController(
        new Verifier($storage),
        $secret,
        ['compat-secret-42' => 'login'],
        $storage,
        null,
        $metadataStore,
        null,
        null,
        2.0,
        0,
        null,
        null,
        null,
        null,
        null,
        // Fixture-only: capture the actual first core VerifyOutcome plus
        // the controller's verification context, so a failed siteverify
        // logs the real error code (never the provider-collapsed
        // invalid-input-response) and the surrounding context.
        static function (\KiwiCaptcha\VerifyOutcome $outcome, array $context): void {
            $GLOBALS['kiwi_last_siteverify_outcome'] = [
                'code' => $outcome->isOk() ? 'ok' : $outcome->code(),
                'context' => $context,
            ];
        },
    );
    // A successful verification consumes the record (single-use); the
    // fixture's file stands in for the shared retained-state store, so the
    // record is removed only after a successful redemption (the controller
    // must see the pending record to verify it). The request carries the
    // RAW application/x-www-form-urlencoded body exactly like the
    // production wire: SiteVerify deliberately fails closed when it is
    // asked to trust a populated framework form bag without the original
    // raw body (duplicate/bracket ambiguity can then no longer be proven
    // absent), so the fixture must never use the 3rd-arg parameter bag.
    $params = [
        'secret' => (string) ($body['secret'] ?? ''),
        'response' => (string) ($body['response'] ?? ''),
        'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'),
        'action' => $body['action'] ?? null,
    ];
    $rawBody = http_build_query($params);
    $GLOBALS['kiwi_last_siteverify_predecode']['rebuilt_token_sha256'] = hash('sha256', (string) ($params['response'] ?? ''));
    $request = \Symfony\Component\HttpFoundation\Request::create(
        '/kiwi-captcha/siteverify',
        'POST',
        [],
        [],
        [],
        ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
        $rawBody,
    );
    $response = $controller->siteverify($request);
    // The form path's own outcome, snapshotted before any bisect: the
    // diagnostic must report the form call's observer state, not the
    // last (possibly bisect-overwritten) write.
    $GLOBALS['kiwi_last_siteverify_form_outcome'] = $GLOBALS['kiwi_last_siteverify_outcome'] ?? null;
    $GLOBALS['kiwi_last_siteverify_form_probe'] = $GLOBALS['kiwi_last_siteverify_probe'] ?? null;
    // Fixture-only: replicate the controller's strict form decoder on the
    // rebuilt form body and log the decoded response token's sha — if it
    // differs from the original, the form wire mangles the token on this
    // runner (the controller then fails the decode).
    $GLOBALS['kiwi_last_siteverify_strict_decoded_sha'] = null;
    // Fixture-only bisect matrix: (a) form without the action field, (b)
    // JSON with the action+cdata — isolating whether the action field or
    // the form content-type is the differentiator on this runner.
    $GLOBALS['kiwi_last_siteverify_bisect_form_noaction'] = null;
    $GLOBALS['kiwi_last_siteverify_bisect_form_match'] = null;
    $GLOBALS['kiwi_last_siteverify_bisect_form_mismatch'] = null;
    $GLOBALS['kiwi_last_siteverify_bisect_json_action'] = null;
    foreach ([
        'noaction' => http_build_query(['secret' => (string) ($body['secret'] ?? ''), 'response' => (string) ($body['response'] ?? ''), 'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1')]),
        'match' => http_build_query(['secret' => (string) ($body['secret'] ?? ''), 'response' => (string) ($body['response'] ?? ''), 'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), 'action' => 'checkout']),
        'mismatch' => http_build_query(['secret' => (string) ($body['secret'] ?? ''), 'response' => (string) ($body['response'] ?? ''), 'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), 'action' => 'admin']),
    ] as $label => $bisectBody) {
        try {
            $bRequest = \Symfony\Component\HttpFoundation\Request::create('/kiwi-captacha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], $bisectBody);
            $bPayload = json_decode((string) $controller->siteverify($bRequest)->getContent(), true);
            $result = ($bPayload['success'] ?? null) === true ? 'ok' : ($bPayload['error-codes'][0] ?? '?');
            $GLOBALS['kiwi_last_siteverify_bisect_form_'.$label] = $result;
        } catch (\Throwable $e) {
            $GLOBALS['kiwi_last_siteverify_bisect_form_'.$label] = 'exception:'.get_class($e);
        }
    }
    try {
        $jsonAction = json_encode(['secret' => (string) ($body['secret'] ?? ''), 'response' => (string) ($body['response'] ?? ''), 'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), 'action' => 'admin', 'cdata' => 'forged'], JSON_THROW_ON_ERROR);
        $jaRequest = \Symfony\Component\HttpFoundation\Request::create('/kiwi-captacha/siteverify', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $jsonAction);
        $jaPayload = json_decode((string) $controller->siteverify($jaRequest)->getContent(), true);
        $GLOBALS['kiwi_last_siteverify_bisect_json_action'] = ($jaPayload['success'] ?? null) === true ? 'ok' : ($jaPayload['error-codes'][0] ?? '?');
    } catch (\Throwable $e) {
        $GLOBALS['kiwi_last_siteverify_bisect_json_action'] = 'exception:'.get_class($e);
    }
    try {
        $strictToken = null;
        foreach (explode('&', $rawBody) as $pair) {
            $parts = explode('=', $pair, 2);
            $name = rawurldecode($parts[0]);
            if ($name === 'response') {
                $component = $parts[1] ?? '';
                $component = str_replace('+', ' ', $component);
                $strictToken = preg_replace_callback('/%([0-9A-Fa-f]{2})/', static fn (array $m): string => chr(hexdec($m[1])), $component);
                break;
            }
        }
        $GLOBALS['kiwi_last_siteverify_strict_decoded_sha'] = $strictToken !== null ? hash('sha256', $strictToken) : 'response-missing';
    } catch (\Throwable $e) {
        $GLOBALS['kiwi_last_siteverify_strict_decoded_sha'] = 'decode-exception:'.get_class($e);
    }
    //the same logical request as JSON (the original
    // wire) — if the form path rejects but the JSON path succeeds, the
    // strict form decoder is the differentiator on this runner.
    $GLOBALS['kiwi_last_siteverify_json_bisect'] = null;
    try {
        $jsonBody = json_encode(['secret' => (string) ($body['secret'] ?? ''), 'response' => (string) ($body['response'] ?? ''), 'remoteip' => (string) ($body['remoteip'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1')], JSON_THROW_ON_ERROR);
        $jsonRequest = \Symfony\Component\HttpFoundation\Request::create(
            '/kiwi-captacha/siteverify',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            $jsonBody,
        );
        $jsonResponse = $controller->siteverify($jsonRequest);
        $jsonPayload = json_decode((string) $jsonResponse->getContent(), true);
        $GLOBALS['kiwi_last_siteverify_json_bisect'] = $jsonPayload['success'] ?? null;
    } catch (\Throwable $e) {
        $GLOBALS['kiwi_last_siteverify_json_bisect'] = 'bisect-exception:'.get_class($e);
    }
    // Provider-compatible SiteVerify semantics return validation failures
    // as HTTP 200 with success:false — the fixture must gate its
    // single-use state on the JSON payload, never the HTTP status.
    $payload = json_decode((string) $response->getContent(), true);
    $success = is_array($payload) && ($payload['success'] ?? false) === true;
    if ($success) {
        @unlink(recordFile($nonce));
        @unlink(metadataFile($nonce));
    } else {
        // Diagnostic only (never through production responses): the
        // controller's fixture-only observer captured the actual first
        // core VerifyOutcome with the verification context before the
        // provider conversion, logged verbatim. The public provider
        // payload stays collapsed.
        $recorded = $GLOBALS['kiwi_last_siteverify_outcome'] ?? null;
        $preDecode = $GLOBALS['kiwi_last_siteverify_predecode'] ?? null;
        $probe = $GLOBALS['kiwi_last_siteverify_probe'] ?? null;
        $rebuiltSha = $GLOBALS['kiwi_last_siteverify_predecode']['rebuilt_token_sha256'] ?? 'n/a';
        $bisect = $GLOBALS['kiwi_last_siteverify_json_bisect'] ?? 'n/a';
        $strictSha = $GLOBALS['kiwi_last_siteverify_strict_decoded_sha'] ?? 'n/a';
        $formOutcome = $GLOBALS['kiwi_last_siteverify_form_outcome'] ?? null;
        $formOutcomeCode = $formOutcome['code'] ?? 'no-observer';
        $bNoAction = $GLOBALS['kiwi_last_siteverify_bisect_form_noaction'] ?? 'n/a';
        $bMatch = $GLOBALS['kiwi_last_siteverify_bisect_form_match'] ?? 'n/a';
        $bMismatch = $GLOBALS['kiwi_last_siteverify_bisect_form_mismatch'] ?? 'n/a';
        $bJsonAction = $GLOBALS['kiwi_last_siteverify_bisect_json_action'] ?? 'n/a';
        $tokenProfile = sprintf('+%d/%%%d/=%d/_%d/-%d', $preDecode['token_plus'] ?? -1, $preDecode['token_slash'] ?? -1, $preDecode['token_eq'] ?? -1, $preDecode['token_underscore'] ?? -1, $preDecode['token_dash'] ?? -1);
        $diagnostic = $formOutcome !== null
            ? sprintf('form_code=%s form_context=%s probe=%s json_bisect=%s strict_sha=%s noaction=%s match=%s mismatch=%s json_action=%s token=%s', $formOutcomeCode, json_encode($formOutcome['context'] ?? null), $probe ?? 'n/a', var_export($bisect, true), $strictSha, $bNoAction, $bMatch, $bMismatch, $bJsonAction, $tokenProfile)
            : ($preDecode !== null
                ? sprintf('pre-decode: len=%d sha256=%s rebuilt_sha=%s strict_sha=%s decode=%s ct=%s raw_len=%d probe=%s json_bisect=%s noaction=%s match=%s mismatch=%s json_action=%s token=%s', $preDecode['response_len'], $preDecode['response_sha256'], $rebuiltSha, $strictSha, $preDecode['decode'], $preDecode['content_type'], $preDecode['raw_len'], $probe ?? 'n/a', var_export($bisect, true), $bNoAction, $bMatch, $bMismatch, $bJsonAction, $tokenProfile)
                : 'no outcome recorded');
        error_log(sprintf('kiwicaptcha-browser-fixture: siteverify internal outcome: %s (provider payload: %s)', $diagnostic, json_encode($payload)));
    }
    echo $response->getContent();

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/honeypot-check') {
    // The form-submission honeypot fixture: the mirror of the bundle
    // validator's formDecoyEvidence. After a valid verification the
    // submitted form is checked for a non-empty value under the exact
    // authenticated decoy name of the verified outcome (the protocol-v3
    // record's decoyField, the same name the challenge response
    // carried). Any other field name is ignored: a decoy name is
    // server-issued and a mismatched name is not this challenge's
    // decoy. Evidence only, never a gate: the proof outcome decides.
    $rawBody = (string) file_get_contents('php://input');
    $body = json_decode($rawBody, true);
    $fields = [];
    if (is_array($body) && isset($body['form']) && is_array($body['form'])) {
        $fields = $body['form'];
    } else {
        parse_str($rawBody, $fields);
    }
    header('Content-Type: application/json');
    $token = (isset($fields['kiwi__token']) && is_string($fields['kiwi__token'])) ? $fields['kiwi__token'] : '';
    if ($token === '' && is_array($body) && isset($body['token']) && is_string($body['token'])) {
        $token = $body['token'];
    }
    $nonce = (string) (explode('.', (string) base64_decode($token, true))[0] ?? '');
    if ($nonce === '' || !is_file(recordFile($nonce))) {
        echo json_encode(['ok' => false, 'code' => 'record_not_found']);

        return true;
    }
    $storage = new ArrayStorage();
    $record = \KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($nonce)), true));
    $storage->store($record);
    $scope = (isset($body['scope']) && is_string($body['scope'])) ? $body['scope'] : 'login';
    $outcome = (new Verifier($storage))->verify($token, $secret, $scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), expectedRequestBinding: $record->requestBinding);
    if ($outcome->isOk()) {
        @unlink(recordFile($nonce));
    } else {
        echo json_encode(['ok' => false, 'code' => $outcome->code()]);

        return true;
    }
    $decoyField = \method_exists($outcome, 'decoyField') ? $outcome->decoyField() : null;
    $honeypotHit = false;
    if (\is_string($decoyField) && $decoyField !== '') {
        // Array-shaped parameters under the decoy name (e.g.
        // billing_address_line[]=x) are not a scalar decoy value: the
        // deterministic answer is no hit, never an error. A forced
        // same-name collision with an application field parses to a
        // single value that may read as a hit; the guarantee is that an
        // accidental collision is impossible (the 64-bit suffix), and
        // the response is always deterministic — never a 500.
        $value = $fields[$decoyField] ?? null;
        $honeypotHit = \is_string($value) && $value !== '';
    }
    echo json_encode(['ok' => true, 'honeypot_hit' => $honeypotHit, 'decoy_field' => $decoyField]);

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/verify') {
    $body = json_decode((string) file_get_contents('php://input'), true);
    header('Content-Type: application/json');
    $nonce = (string) (explode('.', (string) base64_decode((string) ($body['token'] ?? ''), true))[0] ?? '');
    if ($nonce === '' || !is_file(recordFile($nonce))) {
        echo json_encode(['ok' => false, 'code' => 'record_not_found']);

        return true;
    }
    $storage = new ArrayStorage();
    $record = \KiwiCaptcha\ChallengeRecord::fromArray(json_decode((string) file_get_contents(recordFile($nonce)), true));
    $storage->store($record);
    $verifier = new Verifier($storage);
    $scope = (string) ($body['scope'] ?? 'login');
    // The exact-binding contract: a challenge minted bound to a
    // transaction must be redeemed against that same binding (the stored
    // proof's own transaction anchor — the production canonical binding
    // would come from the request's authoritative resolution; the
    // fixture's verify endpoint uses the stored value). The fixture
    // record survives the attempt: it is removed only after a genuinely
    // successful verification (a cheap failure must not destroy the
    // retained state — the production model never deletes on request).
    $outcome = $verifier->verify((string) ($body['token'] ?? ''), $secret, $scope, (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), expectedRequestBinding: $record->requestBinding);
    if ($outcome->isOk()) {
        @unlink(recordFile($nonce));
    }
    echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);

    return true;
}

if ($path === '/kiwi-worker.js' || $path === '/kiwicaptcha-wasm.js' || $path === '/kiwi-worker-stale.js') {
    $name = $path === '/kiwi-worker.js' ? 'kiwi-worker.js' : ($path === '/kiwicaptcha-wasm.js' ? 'kiwicaptcha-wasm.js' : 'kiwi-worker.js');
    $file = $repo.'/packages/kiwicaptcha-wasm/assets/'.$name;
    if (!is_file($file)) {
        http_response_code(404);
        echo 'not found';

        return true;
    }
    header('Content-Type: application/javascript');
    header('Cache-Control: no-store');
    $body = file_get_contents($file);
    // /kiwi-worker-stale.js serves the real worker with the solver build id
    // rewritten: the driver must refuse it with the controlled
    // kiwi:solver-mismatch state instead of accepting a stale worker.
    if ($path === '/kiwi-worker-stale.js') {
        $body = str_replace('2026-08-r2', '2026-08-r0', (string) $body);
    }
    echo $body;

    return true;
}

// ── Files-mode versioned asset route (asset_mode "files") ──────────────
// GET /kiwi-captcha/assets/{name}.{sha256-64}.{js|css} serves the exact
// bytes the inline page embeds, with the full 256-bit content hash in the
// URL, a long immutable cache lifetime, the Content-Length and the
// content-hash ETag. An unknown hash is a 404, exactly like the bundle's
// AssetController (the fixture mirrors the bundle route; the spec asserts
// the headers, the 404 and the 304 revalidation).
$assetSpecs = [
    'widget' => ['file' => 'widget.css', 'type' => 'text/css; charset=UTF-8'],
    'runtime' => ['file' => 'kiwicaptcha-wasm.js', 'type' => 'application/javascript; charset=UTF-8'],
    'driver' => ['file' => 'widget-driver.js', 'type' => 'application/javascript; charset=UTF-8'],
    'worker' => ['file' => 'kiwi-worker.js', 'type' => 'application/javascript; charset=UTF-8'],
    'execution' => ['file' => 'execution-interpreter.js', 'type' => 'application/javascript; charset=UTF-8'],
];
if (preg_match('~^/kiwi-captcha/assets/(widget|runtime|driver|worker|execution)\.([0-9a-f]{64})\.(js|css)$~', $path, $m) === 1) {
    [, $assetName, $assetHash, $assetExt] = $m;
    $spec = $assetSpecs[$assetName];
    if (($assetName === 'widget' ? 'css' : 'js') !== $assetExt) {
        http_response_code(404);
        echo 'not found';

        return true;
    }
    $assetBody = @file_get_contents($repo.'/packages/kiwicaptcha-wasm/assets/'.$spec['file']);
    if ($assetBody === false || $assetBody === '') {
        http_response_code(404);
        echo 'not found';

        return true;
    }
    $assetFull = hash('sha256', $assetBody);
    // The URL hash is the full 256-bit digest, the same value as the
    // ETag below, so a URL can only address the exact served bytes.
    if (!hash_equals($assetFull, $assetHash)) {
        http_response_code(404);
        echo 'not found';

        return true;
    }
    $assetEtag = '"'.$assetFull.'"';
    if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $assetEtag) {
        header('ETag: '.$assetEtag);
        header('Cache-Control: public, max-age=31536000, immutable');
        http_response_code(304);

        return true;
    }
    header('Content-Type: '.$spec['type']);
    header('Cache-Control: public, max-age=31536000, immutable');
    header('ETag: '.$assetEtag);
    header('Content-Length: '.\strlen($assetBody));
    header('X-Content-Type-Options: nosniff');
    echo $assetBody;

    return true;
}

// Incumbent-compatibility loader + migration fixtures.
$assets = $repo.'/packages/kiwicaptcha-wasm/assets';

// The compat endpoints go through the real bundle
// controller — the hard-coded concat hid a production route
// failure (a missing Request import broke the actual routes).
$symfonyAutoload = $repo.'/packages/kiwicaptcha/integrations/symfony/vendor/autoload.php';
if (($path === '/kiwi-captcha/api.js' || $path === '/kiwi-captcha/widget.css') && is_file($symfonyAutoload)) {
    require $symfonyAutoload;
    $api = new \BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController($assets);
    $srequest = \Symfony\Component\HttpFoundation\Request::create(
        $_SERVER['REQUEST_URI'],
        $_SERVER['REQUEST_METHOD'] ?? 'GET',
        [],
        [],
        [],
        $_SERVER,
    );
    $sresponse = $path === '/kiwi-captcha/api.js' ? $api->apiJs($srequest) : $api->widgetCss($srequest);
    foreach ($sresponse->headers->all() as $name => $values) {
        header($name.': '.implode(', ', $values));
    }
    http_response_code($sresponse->getStatusCode());
    echo $sresponse->getContent();

    return true;
}
if (preg_match('~^/migration/(recaptcha-v2|recaptcha-v2-ttl|recaptcha-v2-argon|recaptcha-v2-explicit|recaptcha-invisible|recaptcha-v3|hcaptcha|turnstile|turnstile-meta)\.html$~', $path, $m) === 1) {
    header('Content-Type: text/html');
    header('Cache-Control: no-store');
    $html = file_get_contents(__DIR__.'/migration/'.$m[1].'.html');
    // Page-level loader parameters (hl, render, onload) are
    // propagated into the fixture's api.js URL — the incumbent pattern
    // puts them on the script URL, and the fixture HTML cannot know the
    // test's query string.
    $pageParams = $_GET;
    if (isset($pageParams['hl']) || isset($pageParams['render']) || isset($pageParams['onload'])) {
        $extra = [];
        foreach (['hl', 'render', 'onload'] as $p) {
            if (isset($pageParams[$p]) && is_string($pageParams[$p])) {
                $extra[] = $p.'='.rawurlencode($pageParams[$p]);
            }
        }
        if ($extra !== []) {
            $html = preg_replace('~(<script src=")([^"]*api\.js)([^"]*)(")~', '$1$2$3&'.implode('&', $extra).'$4', $html, 1);
        }
    }
    echo $html;

    return true;
}

if ($path === '/' || $path === '/index.html') {
    $assets = $repo.'/packages/kiwicaptcha-wasm/assets';
    $css = file_get_contents($assets.'/widget.css');
    $wasm = file_get_contents($assets.'/kiwicaptcha-wasm.js');
    $driver = file_get_contents($assets.'/widget-driver.js');
    $csp = ($_GET['csp'] ?? '') === 'strict'
        ? '<meta http-equiv="Content-Security-Policy" content="script-src \'unsafe-inline\'; style-src \'unsafe-inline\'">'
        : '';
    $algorithm = ($_GET['algorithm'] ?? '') === 'argon2id' ? 'argon2id' : 'sha256';
    $workerAttr = '';
    if (($_GET['worker'] ?? '') === '1') $workerAttr = ' data-kiwi-worker-src="/kiwi-worker.js"';
    if (($_GET['worker-stale'] ?? '') === '1') $workerAttr = ' data-kiwi-worker-src="/kiwi-worker-stale.js"';
    $binding = ($_GET['binding'] ?? '') !== '' ? ' data-kiwi-request-binding="'.htmlspecialchars((string) $_GET['binding'], ENT_QUOTES).'"' : '';
    $lang = ($_GET['lang'] ?? '') !== '' ? ' data-kiwi-lang="'.htmlspecialchars((string) $_GET['lang'], ENT_QUOTES).'"' : '';
    // Risk-v2 fixture knobs: ?decoy=1 emits the decoy field in the
    // challenge response, ?ttl=<s> shortens the challenge lifetime (the
    // expiry-driven re-solve test), ?capture=<name> records the challenge
    // request bodies, ?chain=<ticket> seeds the container with
    // data-kiwi-chain-ticket, and ?risk-context=coarse seeds the container
    // with the explicit data-kiwi-risk-context="coarse" opt-in attribute
    // (without it the driver never sends client_context).
    $endpointQuery = [];
    $decoyParam = (string) ($_GET['decoy'] ?? '');
    if ($decoyParam === '1' || $decoyParam === 'pool') $endpointQuery[] = 'decoy='.$decoyParam;
    if (($_GET['decoyname'] ?? '') !== '') $endpointQuery[] = 'decoyname='.rawurlencode((string) $_GET['decoyname']);
    if (($_GET['strategy'] ?? '') !== '' && ctype_digit((string) $_GET['strategy'])) $endpointQuery[] = 'strategy='.rawurlencode((string) $_GET['strategy']);
    if (($_GET['chaining'] ?? '') === '1') $endpointQuery[] = 'chaining=1';
    if (($_GET['ttl'] ?? '') !== '') $endpointQuery[] = 'ttl='.rawurlencode((string) $_GET['ttl']);
    if (($_GET['capture'] ?? '') !== '') $endpointQuery[] = 'capture='.rawurlencode((string) $_GET['capture']);
    if (($_GET['escalate'] ?? '') === 'argon') $endpointQuery[] = 'escalate=argon';
    if (($_GET['execution'] ?? '') === '1') $endpointQuery[] = 'execution=1';
    // The execution-capability lever (?execution_max_version=<1|2>):
    // propagated to the challenge endpoint so a spec can simulate a
    // stale page whose driver never advertises the version-2
    // capability (the fixture then issues version-1 programs).
    if (($_GET['execution_max_version'] ?? '') !== '' && ctype_digit((string) $_GET['execution_max_version'])) $endpointQuery[] = 'execution_max_version='.rawurlencode((string) $_GET['execution_max_version']);
    // Client-performance-lab difficulty knobs, propagated to the
    // challenge endpoint (opt-in; absent = the historical fixture):
    // ?bits=<1..20> (SHA-256 target bits), ?argon_bits=<1..10> and
    // ?m_kib=<8..65536> (Argon2id target bits and memory envelope).
    foreach (['bits', 'argon_bits', 'm_kib'] as $labKnob) {
        if (($_GET[$labKnob] ?? '') !== '' && ctype_digit((string) $_GET[$labKnob])) {
            $endpointQuery[] = $labKnob.'='.rawurlencode((string) $_GET[$labKnob]);
        }
    }
    // Multi-widget page (opt-in): ?widgets=N renders N widget
    // containers, all auto-initialized by the driver (the
    // client-performance lab's multiple-widget scenario). The default
    // N=1 keeps the historical single-container markup byte-identical.
    $widgets = (int) ($_GET['widgets'] ?? 1);
    if ($widgets < 1 || $widgets > 4) $widgets = 1;
    $endpoint = '/challenge'.($endpointQuery !== [] ? '?'.implode('&', $endpointQuery) : '');
    $chainAttr = ($_GET['chain'] ?? '') !== '' ? ' data-kiwi-chain-ticket="'.htmlspecialchars((string) $_GET['chain'], ENT_QUOTES).'"' : '';
    $riskContextAttr = ($_GET['risk-context'] ?? '') === 'coarse' ? ' data-kiwi-risk-context="coarse"' : '';
    // Files-mode variant (?assets=files): mirrors the bundle theme's
    // files tier — the stylesheet link and the driver script are emitted
    // once (the page-level dedup registry), the runtime and the worker
    // stay lazy (data-kiwi-runtime-src + data-kiwi-worker-src with their
    // SRI digests on each container; the driver fetches them only when a
    // memory-hard challenge arrives), and the inline style/script blocks
    // are omitted.
    $filesMode = ($_GET['assets'] ?? '') === 'files';
    $assetTags = '';
    $runtimeAttr = '';
    $workerAttrFiles = '';
    if ($filesMode) {
        $assetFiles = [
            'widget' => 'widget.css',
            'runtime' => 'kiwicaptcha-wasm.js',
            'driver' => 'widget-driver.js',
            'worker' => 'kiwi-worker.js',
            'execution' => 'execution-interpreter.js',
        ];
        $assetLink = static function (string $name, string $ext) use ($repo, $assetFiles): array {
            $body = (string) file_get_contents($repo.'/packages/kiwicaptcha-wasm/assets/'.$assetFiles[$name]);
            $full = hash('sha256', $body);

            return [
                'url' => '/kiwi-captcha/assets/'.$name.'.'.$full.'.'.$ext,
                'sri' => 'sha256-'.base64_encode(hash('sha256', $body, true)),
            ];
        };
        $widgetAsset = $assetLink('widget', 'css');
        $driverAsset = $assetLink('driver', 'js');
        $runtimeAsset = $assetLink('runtime', 'js');
        $workerAsset = $assetLink('worker', 'js');
        $executionAsset = $assetLink('execution', 'js');
        $assetTags = '<link rel="stylesheet" href="'.$widgetAsset['url'].'" integrity="'.$widgetAsset['sri'].'">'."\n"
            .'<script src="'.$driverAsset['url'].'" integrity="'.$driverAsset['sri'].'"></script>'."\n";
        $runtimeAttr = ' data-kiwi-runtime-src="'.$runtimeAsset['url'].'" data-kiwi-runtime-integrity="'.$runtimeAsset['sri'].'"';
        $workerAttrFiles = ' data-kiwi-worker-src="'.$workerAsset['url'].'" data-kiwi-worker-integrity="'.$workerAsset['sri'].'"';
        // The ExecutionChallengeV1 interpreter asset stays lazy in the
        // files tier (exactly like the runtime/worker): its URL + SRI
        // ride the container and the driver fetches it only when an
        // armed challenge arrives (a SHA-only page pays zero bytes).
        $executionAttrFiles = ' data-kiwi-execution-src="'.$executionAsset['url'].'" data-kiwi-execution-integrity="'.$executionAsset['sri'].'"';
    } else {
        $executionAttrFiles = '';
    }
    header('Content-Type: text/html');
    $containers = '';
    for ($i = 1; $i <= $widgets; ++$i) {
        $containerId = $widgets === 1 ? 'kiwicaptcha-root' : 'kiwicaptcha-root-'.$i;
        $containers .= "<div class=\"kiwi-container\" id=\"{$containerId}\" data-kiwi-endpoint=\"{$endpoint}\" data-kiwi-scope=\"login\" data-kiwi-algorithm=\"{$algorithm}\"{$workerAttr}{$binding}{$lang}{$chainAttr}{$riskContextAttr}{$runtimeAttr}{$workerAttrFiles}{$executionAttrFiles}>
  <input type=\"hidden\" name=\"kiwi__token\" data-kiwi-token value=\"\" />
  <div class=\"kiwi-widget\" data-kiwi-widget data-state=\"idle\">
    <div class=\"kiwi-icon-wrapper\"><svg></svg><div class=\"kiwi-glow\"></div></div>
    <div class=\"kiwi-main\">
      <div class=\"kiwi-top\"><span class=\"kiwi-label\" data-kiwi-label>Security Check</span><span class=\"kiwi-badge\" data-kiwi-badge>Idle</span></div>
      <div class=\"kiwi-track\" aria-hidden=\"true\"><div class=\"kiwi-bar\" data-kiwi-bar></div></div>
      <div class=\"kiwi-bottom\"><p class=\"kiwi-info\" data-kiwi-info>Protected</p><span class=\"kiwi-timer\" data-kiwi-timer></span></div>
    </div>
  </div>
</div>
";
    }
    $inlineScripts = $filesMode ? '' : '<script>'.$wasm.'</script><script>'.$driver.'</script>';
    echo "<!DOCTYPE html><html lang=\"en\"><head><title>KiwiCaptcha widget test page</title><style>{$css}</style>{$csp}{$assetTags}</head><body>
{$containers}{$inlineScripts}</body></html>";

    return true;
}

http_response_code(404);
echo 'not found';

return true;
