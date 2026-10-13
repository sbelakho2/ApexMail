<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The request-scoped routing table between the validator's step-up
 * demand minting and the form fields that render the widget.
 *
 * When a submission is answered with a step-up demand, the demand
 * belongs to exactly one protected form: on a page with several captcha
 * fields, each refused form must surface its own demand id, never a
 * sibling's. Routing by the form field's local name is not an option
 * (two fields of two forms both spell `captcha`), and the validator
 * cannot ask the form for its field instance: the constraint validator
 * never receives a reliable FormInterface reference. The shared
 * identity is instead the constraint instance itself, which is exactly
 * the stable, server-side field-instance identity both sides hold. The
 * form integration creates one KiwiCaptcha constraint per field (the
 * type's options closure), and the validator receives that very
 * instance with the value it judges. The field's finishView() reads
 * the same instance back off the form config and claims exactly its
 * entry.
 *
 * The table lives on the main request's attributes, so it is scoped to
 * one request by construction and carries no state across requests.
 * A claim removes its entry: a demand id is rendered once, by the one
 * field whose constraint minted it.
 */
final class StepUpDemandViewRegistry
{
    private const ATTRIBUTE = '_kiwi_captcha_step_up_demand_views';

    public function __construct(
        private readonly RequestStack $requestStack,
    ) {
    }

    /**
     * Record the demand id minted under a field instance identity (the
     * constraint instance the validating field carries). A second
     * record for the same identity replaces the first: one field, one
     * live demand.
     */
    public function record(object $fieldInstance, string $demandId): void
    {
        $request = $this->requestStack->getMainRequest();
        if ($request === null) {
            return;
        }
        $table = $request->attributes->get(self::ATTRIBUTE);
        if (!\is_array($table)) {
            $table = [];
        }
        $table[self::identityOf($fieldInstance)] = $demandId;
        $request->attributes->set(self::ATTRIBUTE, $table);
    }

    /**
     * Claim the demand recorded for a field instance identity: the
     * demand id the field's view should surface, or null when this
     * field's validation minted none. The claim removes the entry, so
     * the demand id reaches exactly one rendered view.
     */
    public function claim(object $fieldInstance): ?string
    {
        $request = $this->requestStack->getMainRequest();
        if ($request === null) {
            return null;
        }
        $table = $request->attributes->get(self::ATTRIBUTE);
        if (!\is_array($table)) {
            return null;
        }
        $identity = self::identityOf($fieldInstance);
        if (!\is_string($table[$identity] ?? null)) {
            return null;
        }
        $demandId = $table[$identity];
        unset($table[$identity]);
        $request->attributes->set(self::ATTRIBUTE, $table);

        return $demandId;
    }

    /**
     * The stable server-side identity of a form field instance: the
     * object hash of the constraint instance both the validator and the
     * form integration hold. The instance is referenced by the form
     * config for the whole request, so its hash is stable here.
     */
    private static function identityOf(object $fieldInstance): string
    {
        return spl_object_hash($fieldInstance);
    }
}
