<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

use KiwiCaptcha\Risk\RiskEventKind;

/**
 * The one versioned outcome mapping table: how each of the eight typed
 * outcomes resolves onto the existing risk-v1 event channels, the
 * always-on outcome ledger and the long-memory marks. There is exactly
 * one table — the public enum vocabulary, the engines' feedback
 * channels and the mark behavior can never diverge into a second
 * mapping.
 *
 * The trust polarity lives in this table and is enforced by property
 * tests: only the server-confirmed trust outcomes
 * (confirmedLegitimate, stepUpCompleted, authenticationSuccess) may
 * subtract risk, and exactly the abuse outcomes (spamReported,
 * chargeback, accountBanned, fraudConfirmed) write long-memory marks.
 * The two classes are disjoint: a trust outcome never writes an abuse
 * mark, and an abuse outcome never lowers risk or removes an abuse
 * mark. authenticationSuccess and authenticationFailure map onto the
 * existing authentication feedback channels only and never touch marks.
 *
 * The version constant must rise whenever a row changes meaning; the
 * cross-language vectors (protocol/risk-v1/outcomes-vectors.json) pin
 * both cores to the same table contents.
 */
final class OutcomeMap
{
    public const VERSION = 1;

    private const LEDGER_DIMENSIONS = [
        OutcomeHandleDimension::Nonce,
        OutcomeHandleDimension::DecisionId,
    ];

    private const IDENTITY_DIMENSIONS = [
        OutcomeHandleDimension::Principal,
        OutcomeHandleDimension::Target,
        OutcomeHandleDimension::Session,
        OutcomeHandleDimension::Agent,
    ];

    private const EVERY_DIMENSION = [
        OutcomeHandleDimension::Nonce,
        OutcomeHandleDimension::DecisionId,
        OutcomeHandleDimension::Principal,
        OutcomeHandleDimension::Target,
        OutcomeHandleDimension::Session,
        OutcomeHandleDimension::Agent,
    ];

    /**
     * The table itself, keyed by the outcome wire name. One row per
     * outcome of the vocabulary, in vocabulary order. Built once per
     * process (the rows are immutable value objects).
     *
     * @var array<string, OutcomeMapping>|null
     */
    private static ?array $table = null;

    /** @return array<string, OutcomeMapping> */
    private static function table(): array
    {
        if (self::$table === null) {
            self::$table = [
                'confirmedLegitimate' => new OutcomeMapping(
                    outcome: Outcome::ConfirmedLegitimate,
                    channel: RiskEventKind::ConfirmedLegitimate,
                    ledgerLegitimate: true,
                    writesAbuseMark: false,
                    serverConfirmed: true,
                    maySubtractRisk: true,
                    acceptedHandles: self::EVERY_DIMENSION,
                ),
                'stepUpCompleted' => new OutcomeMapping(
                    outcome: Outcome::StepUpCompleted,
                    channel: RiskEventKind::ProtectedActionSuccess,
                    ledgerLegitimate: null,
                    writesAbuseMark: false,
                    serverConfirmed: true,
                    maySubtractRisk: true,
                    acceptedHandles: self::IDENTITY_DIMENSIONS,
                ),
                'authenticationSuccess' => new OutcomeMapping(
                    outcome: Outcome::AuthenticationSuccess,
                    channel: RiskEventKind::AuthenticationSuccess,
                    ledgerLegitimate: null,
                    writesAbuseMark: false,
                    serverConfirmed: true,
                    maySubtractRisk: true,
                    acceptedHandles: self::IDENTITY_DIMENSIONS,
                ),
                'authenticationFailure' => new OutcomeMapping(
                    outcome: Outcome::AuthenticationFailure,
                    channel: RiskEventKind::AuthenticationFailure,
                    ledgerLegitimate: null,
                    writesAbuseMark: false,
                    serverConfirmed: false,
                    maySubtractRisk: false,
                    acceptedHandles: self::IDENTITY_DIMENSIONS,
                ),
                'spamReported' => new OutcomeMapping(
                    outcome: Outcome::SpamReported,
                    channel: RiskEventKind::ProtectedActionFailure,
                    ledgerLegitimate: null,
                    writesAbuseMark: true,
                    serverConfirmed: true,
                    maySubtractRisk: false,
                    acceptedHandles: self::IDENTITY_DIMENSIONS,
                ),
                'chargeback' => new OutcomeMapping(
                    outcome: Outcome::Chargeback,
                    channel: RiskEventKind::ConfirmedAbuse,
                    ledgerLegitimate: false,
                    writesAbuseMark: true,
                    serverConfirmed: true,
                    maySubtractRisk: false,
                    acceptedHandles: self::EVERY_DIMENSION,
                ),
                'accountBanned' => new OutcomeMapping(
                    outcome: Outcome::AccountBanned,
                    channel: RiskEventKind::ConfirmedAbuse,
                    ledgerLegitimate: false,
                    writesAbuseMark: true,
                    serverConfirmed: true,
                    maySubtractRisk: false,
                    acceptedHandles: self::EVERY_DIMENSION,
                ),
                'fraudConfirmed' => new OutcomeMapping(
                    outcome: Outcome::FraudConfirmed,
                    channel: RiskEventKind::ConfirmedAbuse,
                    ledgerLegitimate: false,
                    writesAbuseMark: true,
                    serverConfirmed: true,
                    maySubtractRisk: false,
                    acceptedHandles: self::EVERY_DIMENSION,
                ),
            ];
        }

        return self::$table;
    }

    /**
     * The mapping row of one outcome. The table is total over the
     * vocabulary, so the lookup always answers a row.
     */
    public static function for(Outcome $outcome): OutcomeMapping
    {
        return self::table()[$outcome->value]
            ?? throw new \LogicException(sprintf('No outcome mapping row for %s', $outcome->value));
    }

    /**
     * Every row, in vocabulary order (the completeness oracle of the
     * property tests and the vector readers).
     *
     * @return list<OutcomeMapping>
     */
    public static function all(): array
    {
        return array_values(self::table());
    }

    /**
     * The ledger dimensions in table order (nonce before decision id).
     *
     * @return list<OutcomeHandleDimension>
     */
    public static function ledgerDimensions(): array
    {
        return self::LEDGER_DIMENSIONS;
    }

    /**
     * The identity dimensions in table order.
     *
     * @return list<OutcomeHandleDimension>
     */
    public static function identityDimensions(): array
    {
        return self::IDENTITY_DIMENSIONS;
    }
}
