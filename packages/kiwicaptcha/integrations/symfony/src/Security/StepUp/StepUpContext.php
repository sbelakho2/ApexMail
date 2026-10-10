<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * One step-up demand: who must step up, under which scope, and why.
 *
 * The identity fields carry pseudonyms only, exactly the shapes the
 * risk engine derives. The principal pseudonym is
 * {@see \KiwiCaptcha\Risk\RiskIdentityFactory::principalId()}, 32
 * lowercase hex chars. The target pseudonym is
 * {@see \KiwiCaptcha\Risk\RiskIdentityFactory::targetId()}, the full
 * 64 lowercase hex char digest. A raw-looking value is rejected at
 * construction, fail-closed, so a raw username or email can never ride
 * a challenge record, a store key or an outcome handle. The one place
 * the target narrows to 32 hex is the outcomes handle/marking key,
 * derived in exactly one function
 * ({@see \BelConsulting\KiwiCaptchaBundle\Risk\TargetMarkKey}).
 */
final class StepUpContext
{
    /** The html presentation mode: begin() renders a form. */
    public const MODE_HTML = 'html';

    /** The json presentation mode: begin() answers a challenge document. */
    public const MODE_JSON = 'json';

    private const MODES = [self::MODE_HTML, self::MODE_JSON];

    public function __construct(
        public readonly string $principalPseudonym,
        public readonly ?string $targetPseudonym,
        public readonly string $scope,
        public readonly ?string $returnPath,
        public readonly string $reason,
        public readonly string $mode = self::MODE_HTML,
        public readonly bool $targetOwned = false,
    ) {
        if (preg_match('/^[0-9a-f]{32}$/D', $principalPseudonym) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                'The principal pseudonym of a step-up context must be 32 lowercase hex chars, never a raw identifier (got 0x%s)',
                bin2hex($principalPseudonym),
            ));
        }
        if ($targetPseudonym !== null && preg_match('/^[0-9a-f]{64}$/D', $targetPseudonym) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                'The target pseudonym of a step-up context must be 64 lowercase hex chars, never a raw identifier (got 0x%s)',
                bin2hex($targetPseudonym),
            ));
        }
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $scope) !== 1) {
            throw new \InvalidArgumentException('The scope of a step-up context must be 1-128 chars of [A-Za-z0-9._:-]');
        }
        if ($returnPath !== null && !self::isSafeReturnPath($returnPath)) {
            throw new \InvalidArgumentException(sprintf(
                'The return path of a step-up context must be an absolute same-site path (got "%s")',
                $returnPath,
            ));
        }
        if (!\in_array($mode, self::MODES, true)) {
            throw new \InvalidArgumentException(sprintf('The presentation mode of a step-up context must be one of %s', implode('|', self::MODES)));
        }
        if (preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $reason) !== 1) {
            throw new \InvalidArgumentException('The reason of a step-up context must be 1-128 chars of [A-Za-z0-9._:-] (e.g. the post_solve_step_up_required violation name)');
        }
    }

    /**
     * The bounded same-site return path rule: absolute, no query, no
     * fragment, no control bytes, no dot segments, no scheme (an
     * absolute path on this origin only, so the completion redirect can
     * never be aimed at a foreign origin).
     */
    public static function isSafeReturnPath(string $path): bool
    {
        if ($path === '' || $path[0] !== '/' || \strlen($path) > 512) {
            return false;
        }
        if (str_contains($path, '\\') || str_contains($path, '?') || str_contains($path, '#')) {
            return false;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
            return false;
        }
        $segments = explode('/', $path);
        for ($i = 1, $count = \count($segments); $i < $count; $i++) {
            if ($segments[$i] === '' || $segments[$i] === '.' || $segments[$i] === '..') {
                return false;
            }
        }

        return true;
    }
}
