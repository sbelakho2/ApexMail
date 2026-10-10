<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

/**
 * SECURITY-MAINTAINER material: the stage-composition matrices are deep
 * design rationale, intentionally not published at the integration layer.
 * See docs/configuration.md "Protection profiles" and change.md Part 5
 * for the operator contract.
 *
 * The profile-driven composition of the adaptive risk engine's decision
 * stages (change.md Part 3). The composed set spans the target
 * identifier resolver, the ASN dataset with the bucket-trust plane, the
 * marks reader with attacker denial, the continuous price model, the
 * names-only explanation surface and the typed outcomes facade.
 * change.md Part 5 mandates that the abuse_first profile turns on
 * everything in Part 3. high_abuse is the same posture under its
 * integration-layer name. The engine's constructor accepts every stage
 * as an optional argument, so the composition is the single place that
 * decides which arguments the bundle actually attaches. An unwired
 * stage keeps the byte-identical plain decision path of the
 * compatibility posture.
 *
 * The resolution rule is uniform for every stage knob: an explicit
 * boolean in any configuration layer always wins, and null (the tree
 * default of every new knob) resolves to the selected profile's matrix.
 * The knobs exist so an operator can deliberately widen a stricter
 * profile (marks under compatibility) or narrow an abuse profile
 * (pricing off under abuse_first) without leaving the composition.
 *
 * The ASN dataset is data, not a flag: the trust and marks stages
 * engage their ASN dimension the moment a dataset path is configured
 * (risk.asn.dataset_path). Without a dataset the price context reads
 * zero bucket trust (fail closed, the price may only raise) and the
 * marks reader drops the asn dimension, so a deployment that does not
 * ship routing-table data loses no other stage.
 */
final class RiskStageComposition
{
    /**
     * The profile matrices. Every profile maps to the same stage
     * vocabulary so the wiring-matrix test can assert the whole table
     * from one source:
     *
     * - abuse_first / high_abuse: everything in change.md Part 3. The
     *   names-only explanation surface rides the gateway too (documented
     *   judgment: the abuse posture trades the additive response field
     *   for operator-visible decisions, and the explanation carries
     *   dimension names only, never a pseudonym). The evidence stage's
     *   browser arm renders "full": the abuse posture collects the
     *   coarse form-level aggregates by default.
     * - balanced / ha_safe / privacy_strict / profile-less: the
     *   server-side memory stages (marks, pricing, bucket trust) attach
     *   whenever the adaptive engine is on. The explanation surface
     *   stays off because balanced promises byte-identical behavior and
     *   the explanation is an operator-facing additive surface. ha_safe
     *   mirrors balanced by contract. privacy_strict keeps the
     *   client-facing behavioral evidence off (its own contract) while
     *   the server-side pseudonymous stages stay on. The ASN dataset is
     *   never required here (no dataset_path, no asn dimension).
     * - compatibility: today's minimal set. Every decision stage stays
     *   unwired so a compatibility deployment keeps the exact engine
     *   pipeline it ran before the stages existed.
     *
     * The evidence-plane entries follow the same uniform rule. The
     * telemetry arm defaults to "minimal" under every profile and to
     * "full" under the abuse postures; the knob (risk.evidence.telemetry)
     * carries the explicit override. The decoy-escalation reader wires
     * with the server-side memory stages (everywhere except
     * compatibility); the write side stays fail-closed through the
     * engine's autofill-qualification gate, so an unwired escalation
     * surface and a closed one are equally inert.
     */
    private const MATRICES = [
        'abuse_first' => ['marks' => true, 'pricing' => true, 'explain' => true, 'telemetry' => 'full', 'decoy' => true],
        'high_abuse' => ['marks' => true, 'pricing' => true, 'explain' => true, 'telemetry' => 'full', 'decoy' => true],
        'balanced' => ['marks' => true, 'pricing' => true, 'explain' => false, 'telemetry' => 'minimal', 'decoy' => true],
        'ha_safe' => ['marks' => true, 'pricing' => true, 'explain' => false, 'telemetry' => 'minimal', 'decoy' => true],
        'privacy_strict' => ['marks' => true, 'pricing' => true, 'explain' => false, 'telemetry' => 'minimal', 'decoy' => true],
        'compatibility' => ['marks' => false, 'pricing' => false, 'explain' => false, 'telemetry' => 'minimal', 'decoy' => false],
    ];

    /** The telemetry vocabulary of the evidence stage's browser arm. */
    public const TELEMETRY_MODES = ['minimal', 'full', 'off'];

    /**
     * The stage plan of one deployment: which engine arguments the
     * extension attaches and whether the gateway surfaces the
     * explanation object.
     *
     * @param string|null           $profile    the selected protection
     *                                          profile (null = the
     *                                          neutral default posture)
     * @param array<string, mixed>  $riskConfig the processed risk config
     *
     * @return array{marks: bool, pricing: bool, trust: bool, asn: bool, explain: bool, telemetry: string, decoy: bool}
     */
    public static function resolve(?string $profile, array $riskConfig): array
    {
        $matrix = self::MATRICES[$profile ?? ''] ?? self::MATRICES['balanced'];
        $asnPath = \is_string($riskConfig['asn']['dataset_path'] ?? null) && $riskConfig['asn']['dataset_path'] !== '';

        return [
            'marks' => self::knob($riskConfig, 'marks', $matrix['marks']),
            'pricing' => self::knob($riskConfig, 'pricing', $matrix['pricing']),
            // The bucket-trust plane rides the pricing stage: the same
            // trust record feeds the price context and nothing else
            // consumes it bundle-side yet. The explicit pricing knob
            // therefore moves trust with it, and the dataset adds the
            // ASN dimension on top.
            'trust' => self::knob($riskConfig, 'pricing', $matrix['pricing']),
            'asn' => $asnPath,
            'explain' => self::explainKnob($riskConfig, $matrix['explain']),
            // The evidence stage's browser arm: the widget container's
            // data-kiwi-telemetry value. The profile matrix fills the
            // null default exactly like the boolean stage knobs; the
            // explicit knob (risk.evidence.telemetry) widens or narrows
            // the derived mode in any config layer.
            'telemetry' => self::telemetryKnob($riskConfig, $matrix['telemetry']),
            // The decoy-escalation reader follows the server-side memory
            // stages: wired with the engine wherever the stage pipeline
            // is composed, never under the compatibility posture. The
            // reader alone cannot arm anything (the canonical script
            // refuses the record op while the qualification gate is
            // closed), so the derived wiring keeps the fail-closed
            // posture.
            'decoy' => $matrix['decoy'],
        ];
    }

    /**
     * One explicit-or-derived stage knob: a configured boolean wins, the
     * profile matrix fills the null default. Anything other than a
     * boolean or null in the processed config is refused by the config
     * tree, so the cast here is a shape restatement, not a conversion.
     */
    private static function knob(array $riskConfig, string $stage, bool $derived): bool
    {
        $explicit = $riskConfig[$stage]['enabled'] ?? null;
        if (\is_bool($explicit)) {
            return $explicit;
        }

        return $derived;
    }

    /**
     * The explanation knob: the profile matrix fills the null default
     * exactly like the stage knobs, so abuse_first surfaces decisions
     * with names-only explanations without any explicit setting.
     */
    private static function explainKnob(array $riskConfig, bool $derived): bool
    {
        $explicit = $riskConfig['explain'] ?? null;
        if (\is_bool($explicit)) {
            return $explicit;
        }

        return $derived;
    }

    /**
     * The evidence telemetry arm: the explicit knob
     * (risk.evidence.telemetry) wins when it names a vocabulary mode,
     * and the profile matrix fills the null default. The config tree
     * refuses every other value, so the guard here restates the shape
     * instead of converting it.
     */
    private static function telemetryKnob(array $riskConfig, string $derived): string
    {
        $explicit = $riskConfig['evidence']['telemetry'] ?? null;
        if (\is_string($explicit) && \in_array($explicit, self::TELEMETRY_MODES, true)) {
            return $explicit;
        }

        return $derived;
    }
}
