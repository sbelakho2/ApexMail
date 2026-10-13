<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;

/**
 * The default delivery seam: logs the delivery instead of mailing, so
 * a deployment without a bound mailer keeps the factor observable and
 * testable. Replace the service binding for real delivery; the code is
 * the only secret and the address the only personal data on the call.
 *
 * The log line carries the address only as a truncated keyed HMAC (16
 * hex chars under the deployment-derived redaction key), never raw: a
 * presented address is personal data, and a log file is not the place
 * it may land. The doctor FAILs a production deployment whose factor
 * resolves to this sender, because a logged code is a code delivered
 * to nobody.
 */
final class LoggingEmailOwnershipCodeSender implements EmailOwnershipCodeSenderInterface
{
    public function __construct(
        private readonly ?LoggerInterface $logger = null,
        private readonly string $hashKey = '',
    ) {
    }

    /**
     * The redacted log shape of a delivered-to address: the first 16
     * hex chars of the keyed HMAC. Deployment-keyed, so the same
     * address hashes differently in two deployments and the value
     * cannot be reversed or cross-referenced.
     */
    public static function hashForLog(string $email, string $hashKey): string
    {
        return substr(hash_hmac('sha256', $email, $hashKey), 0, 16);
    }

    public function send(string $email, string $code, int $ttlSecs, EmailOwnershipDeliveryMetadata $delivery): void
    {
        $this->logger?->info('kiwi email-ownership step-up code generated', [
            'recipient' => self::hashForLog($email, $this->hashKey),
            'expires_in' => $ttlSecs,
            'demand_generation' => $delivery->generation,
        ]);
    }
}
