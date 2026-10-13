<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/**
 * The mailer-backed delivery seam of the anonymous email-ownership
 * factor: hands the code to Symfony Messenger-backed mailer transport
 * addressed to the presented address, which is the identity proof the
 * factor exists to verify. The extension auto-wires this adapter when
 * the symfony/mailer component is installed and no explicit sender is
 * bound; a production build refuses the logging default, so this (or
 * an application sender) always serves production.
 *
 * The From identity is build-time configuration (derived from the
 * canonical public origin), never a request value, so no client input
 * reaches a mail header beyond the recipient itself. The Message-ID is
 * server-minted from the delivery identity:
 * `<kiwi.<base64urlDemandId>.<generation>@message-id-domain>`, under
 * the domain of the configured From address. Every part is dot-atom
 * safe (a base64url demand id, an integer generation, a domain). The
 * id never carries a colon, so the header is valid RFC 5322 and the
 * message is auditable back to the exact demand and escalation
 * generation that funded it.
 *
 * The delivery log carries the address only as the truncated keyed HMAC of
 * {@see LoggingEmailOwnershipCodeSender::hashForLog()}, never raw.
 */
final class MailerEmailOwnershipCodeSender implements EmailOwnershipCodeSenderInterface
{
    public function __construct(
        private readonly MailerInterface $mailer,
        private readonly string $fromAddress,
        private readonly string $hashKey = '',
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function send(string $email, string $code, int $ttlSecs, EmailOwnershipDeliveryMetadata $delivery): void
    {
        // Derive the Message-ID (and refuse a From without a usable domain)
        // before Symfony's Address parser can throw RfcComplianceException
        // on a non-address From. Fail-closed with our own error, matching
        // the documented contract.
        $messageId = $this->messageId($delivery);
        $minutes = max(1, (int) ceil($ttlSecs / 60));
        $message = new Email();
        try {
            $message->from($this->fromAddress);
        } catch (\Throwable $e) {
            throw new \RuntimeException(sprintf(
                'The mailer email-ownership sender cannot derive a Message-ID domain from the configured From identity; set a deliverable from address (got a From without a usable domain)',
            ), 0, $e);
        }
        $message
            ->to($email)
            ->subject('Your verification code')
            ->text(sprintf(
                "Your verification code is %s. It expires in %d minute(s).\n\nIf you did not request this code, you can ignore this message.",
                $code,
                $minutes,
            ));
        $message->getHeaders()->addIdHeader('Message-ID', trim($messageId, '<>'));
        $this->mailer->send($message);
        $this->logger?->info('kiwi email-ownership step-up code delivered', [
            'recipient' => LoggingEmailOwnershipCodeSender::hashForLog($email, $this->hashKey),
            'expires_in' => $ttlSecs,
            'demand_generation' => $delivery->generation,
        ]);
    }

    /**
     * The Message-ID of one delivery: the server-minted local part over
     * the configured From identity's domain. The From address is
     * build-time configuration, so the domain never derives from a
     * request value; a From without a domain refuses the delivery
     * fail-closed rather than sending an unidentifiable message.
     */
    private function messageId(EmailOwnershipDeliveryMetadata $delivery): string
    {
        $at = strrpos($this->fromAddress, '@');
        $domain = $at === false ? '' : substr($this->fromAddress, $at + 1);
        if ($domain === '' || preg_match('/^[A-Za-z0-9.-]+$/D', $domain) !== 1) {
            throw new \RuntimeException(sprintf(
                'The mailer email-ownership sender cannot derive a Message-ID domain from the configured From identity; set a deliverable from address (got a From without a usable domain)',
            ));
        }

        return $delivery->messageIdLocalPart().'@'.strtolower($domain);
    }
}
