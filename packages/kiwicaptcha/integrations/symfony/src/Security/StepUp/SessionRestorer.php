<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use KiwiCaptcha\Risk\Asn\AsnDataset;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\Storage\PrincipalNetworkTagStoreInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * The step-up session restore: after a factor completes, a pending
 * token is unwrapped back into the real authenticated token and the
 * network bucket is recorded so the next login from the same network
 * is no longer novel. Without the restore a legitimate user on a novel
 * network would stay pending forever and be stepped up on every login.
 */
final class SessionRestorer
{
    public function __construct(
        private readonly RiskIdentityFactory $identityFactory,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        private readonly ?PrincipalNetworkTagStoreInterface $principalNetworks = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?RequestStack $requestStack = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?AsnDataset $asnDataset = null,
    ) {
    }

    /**
     * Restore the wrapped token and record the network bucket. No-op
     * when the current token is not pending (a plain step-up inside an
     * already-authenticated session) or when a seam is missing.
     */
    public function restore(string $principalPseudonym, ?Request $request = null): void
    {
        try {
            $token = $this->tokenStorage?->getToken();
            if ($token instanceof StepUpPendingToken) {
                // The pending token's principal must be the one that
                // completed the step-up: a stolen ticket for another
                // account can never upgrade this session.
                // The token carries the raw user identifier; the
                // challenge carries the 32-hex principal pseudonym.
                // Compare like with like or every restore fails.
                $pendingRaw = $token->getUserIdentifier();
                $pendingPrincipal = $this->identityFactory->principalId($pendingRaw);
                if ($principalPseudonym !== '' && $pendingPrincipal !== ''
                    && !hash_equals($pendingPrincipal, $principalPseudonym)) {
                    $this->logger?->warning('kiwi step-up session restore refused: principal mismatch');

                    return;
                }
                $this->tokenStorage?->setToken($token->getWrapped());
            }
            $request ??= $this->requestStack?->getCurrentRequest();
            // Rotate the session id on the privilege upgrade so a
            // fixation captured before the step-up cannot ride the new
            // session. Runs after the request-stack fallback so a caller
            // that omitted the request still gets the rotation.
            if ($token instanceof StepUpPendingToken && $request !== null && $request->hasSession()) {
                $session = $request->getSession();
                if ($session->isStarted()) {
                    $session->migrate(true);
                }
            }
            if ($request === null || $this->principalNetworks === null || $principalPseudonym === '') {
                return;
            }
            $ip = $this->clientIpResolver !== null
                ? $this->clientIpResolver->resolve($request)
                : (string) ($request->getClientIp() ?? '');
            if ($ip === '') {
                return;
            }
            $network = self::networkBucket($ip);
            if ($network !== '') {
                $this->principalNetworks->recordPrincipalNetworkTag($principalPseudonym, $network);
            }
            $asn = $this->asnBucket($ip);
            if ($asn !== '') {
                $this->principalNetworks->recordPrincipalNetworkTag($principalPseudonym, 'asn:'.$asn);
            }
        } catch (\Throwable $e) {
            $this->logger?->warning('kiwi step-up session restore failed: {message}', [
                'message' => $e->getMessage(),
            ]);
        }
    }

    /** The same network bucket spelling as the engine. */
    private static function networkBucket(string $ip): string
    {
        $packed = inet_pton($ip);
        if ($packed === false) {
            return '';
        }
        if (\strlen($packed) === 4) {
            return bin2hex("\x04".$packed);
        }

        return bin2hex("\x06".substr($packed, 0, 8));
    }

    /**
     * The ASN tag spelling of the engine's novel-network gate
     * ({@see \KiwiCaptcha\Risk\AdaptiveRiskEngine}): the ASN number when
     * the dataset resolved one, else the bucket id. The restorer must
     * record exactly the key the engine later looks up — compare like
     * with like, or the second login stays novel forever.
     */
    private function asnBucket(string $ip): string
    {
        if ($this->asnDataset === null) {
            return '';
        }
        try {
            $info = $this->asnDataset->lookup($ip);

            return (string) ($info->asn ?? $info->bucket);
        } catch (\Throwable) {
            return '';
        }
    }
}
