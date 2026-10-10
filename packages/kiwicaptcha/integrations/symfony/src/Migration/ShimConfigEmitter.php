<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Migration;

/**
 * Turns scanner findings into the ready-to-paste shim config: the
 * client script block, the sitekey-to-scope mapping table and the
 * server-side siteverify swap instructions. Text and JSON formats
 * carry the same information.
 *
 * The client block points at the kiwi deployment's compat loader,
 * `GET {prefix}/api.js?compat={provider}`: one URL swap per provider
 * script, with the detected sitekeys mapped to scopes through the
 * loader's data-kiwi-scope-map attribute. An unmapped sitekey is
 * presented verbatim, so a deployment can also resolve scopes through
 * its own sitekey allowlist. The altcha and friendly captcha surfaces
 * ride the standalone shim asset instead, which recognizes their
 * element conventions without any attribute.
 *
 * The server instructions swap every detected incumbent verify URL
 * for the kiwi deployment's provider-shaped siteverify endpoint
 * (`POST {prefix}/siteverify` with `response`, `secret`, optional
 * `remoteip`), so the response handling code keeps working unchanged.
 */
final class ShimConfigEmitter
{
    /** The compat query value per provider; null rides the standalone shim asset. */
    private const PROVIDER_COMPAT = [
        'recaptcha' => 'recaptcha',
        'hcaptcha' => 'hcaptcha',
        'turnstile' => 'turnstile',
        'altcha' => null,
        'friendly' => null,
    ];

    private const PROVIDER_RESPONSE_FIELD = [
        'recaptcha' => 'g-recaptcha-response',
        'hcaptcha' => 'h-captcha-response (and g-recaptcha-response)',
        'turnstile' => 'cf-turnstile-response',
        'altcha' => 'altcha (the element name attribute)',
        'friendly' => 'frc-captcha-solution',
    ];

    public function __construct(
        private readonly string $prefix = '/kiwi-captcha',
    ) {
    }

    /**
     * Build the structured config document.
     *
     * @param list<array{file: string, line: int, text: string, provider: string, kind: string, scope: string}> $findings
     *
     * @return array<string, mixed>
     */
    public function build(array $findings, string $root): array
    {
        $scanner = new IncumbentScanner();
        $providers = [];
        foreach ($scanner->providersOf($findings) as $provider) {
            $providerFindings = array_values(array_filter(
                $findings,
                static fn (array $f): bool => $f['provider'] === $provider,
            ));
            $scopeMap = [];
            foreach ($providerFindings as $finding) {
                if ($finding['kind'] !== 'sitekey') {
                    continue;
                }
                $literal = $scanner->sitekeyLiteral($finding['text']);
                if ($literal !== null && !isset($scopeMap[$literal])) {
                    $scopeMap[$literal] = $finding['scope'];
                }
            }
            $providers[] = [
                'provider' => $provider,
                'response_field' => self::PROVIDER_RESPONSE_FIELD[$provider],
                'compat' => self::PROVIDER_COMPAT[$provider],
                'findings' => $providerFindings,
                'sitekeys' => array_keys($scopeMap),
                'scope_map' => $scopeMap ?: null,
                'client_snippet' => $this->clientSnippet($provider, $scopeMap),
                'server_steps' => $this->serverSteps($provider, $providerFindings),
            ];
        }

        return [
            'scanned_root' => $root,
            'siteverify_endpoint' => $this->prefix.'/siteverify',
            'providers' => $providers,
            'notes' => $this->notes(),
        ];
    }

    /**
     * The plain-text report.
     *
     * @param array<string, mixed> $document the build() output
     */
    public function toText(array $document): string
    {
        $lines = [];
        $lines[] = 'KiwiCaptcha migration report';
        $lines[] = 'Scanned root: '.$document['scanned_root'];
        $providers = $document['providers'];
        if ($providers === []) {
            $lines[] = 'No incumbent captcha integrations found. Nothing to migrate.';
        } else {
            $lines[] = 'Detected providers: '.implode(', ', array_map(
                static fn (array $p): string => $p['provider'],
                $providers,
            ));
        }
        $lines[] = '';
        foreach ($providers as $provider) {
            $lines[] = '== '.$provider['provider'].' ==';
            $lines[] = 'Response field kept compatible: '.$provider['response_field'];
            $lines[] = '';
            $lines[] = 'Client swap: point the provider script URL at the kiwi deployment:';
            $lines[] = $provider['client_snippet'];
            $lines[] = '';
            if ($provider['scope_map'] !== null) {
                $lines[] = 'Scope mapping table (data-kiwi-scope-map, sitekey -> scope):';
                foreach ($provider['scope_map'] as $sitekey => $scope) {
                    $lines[] = '  '.$sitekey.' -> '.$scope;
                }
            } else {
                $lines[] = 'Scope mapping: no sitekey literal detected on the matched lines.';
                $lines[] = 'The shim presents an unmapped sitekey verbatim, so the server-side sitekey allowlist resolves it.';
            }
            $lines[] = '';
            $lines[] = 'Server swap: replace the incumbent verify URL with '.$document['siteverify_endpoint'];
            foreach ($provider['server_steps'] as $step) {
                $lines[] = '  - '.$step;
            }
            $lines[] = '';
            $lines[] = 'Matched lines:';
            foreach ($provider['findings'] as $finding) {
                $lines[] = sprintf('  %s:%d [%s] %s', $finding['file'], $finding['line'], $finding['kind'], $finding['text']);
            }
            $lines[] = '';
        }
        foreach ($document['notes'] as $note) {
            $lines[] = 'Note: '.$note;
        }

        return implode("\n", $lines)."\n";
    }

    /**
     * @param array<string, string> $scopeMap
     */
    private function clientSnippet(string $provider, array $scopeMap): string
    {
        $base = rtrim($this->prefix, '/').'/';
        $compat = self::PROVIDER_COMPAT[$provider];
        $attrs = '';
        if ($scopeMap !== []) {
            $attrs = " data-kiwi-scope-map='".json_encode(
                $scopeMap,
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            )."'";
        }
        if ($compat !== null) {
            return sprintf(
                '<script src="%sapi.js?compat=%s"%s defer></script>',
                $base,
                $compat,
                $attrs,
            );
        }

        return sprintf('<script src="%swidget-shims.js"%s defer></script>', $base, $attrs);
    }

    /**
     * @param list<array{file: string, line: int, text: string, provider: string, kind: string, scope: string}> $findings
     *
     * @return list<string>
     */
    private function serverSteps(string $provider, array $findings): array
    {
        $steps = [];
        $verifyUrls = [];
        foreach ($findings as $finding) {
            if ($finding['kind'] !== 'verify') {
                continue;
            }
            if (preg_match('/https?:\/\/[^\s"\']+/', $finding['text'], $m) === 1) {
                $verifyUrls[$m[0]] = true;
            }
        }
        if ($verifyUrls !== []) {
            $steps[] = sprintf(
                'Replace %s with %s (POST form or JSON).',
                implode(' and ', array_keys($verifyUrls)),
                $this->prefix.'/siteverify',
            );
        } else {
            $steps[] = sprintf(
                'Point the %s server-side verification call at %s (POST form or JSON).',
                $provider,
                $this->prefix.'/siteverify',
            );
        }
        $steps[] = 'Send the token in the response parameter, the compatibility secret in the secret parameter.';
        $steps[] = 'Keep sending remoteip when the incumbent call did: the binding stays enforced.';
        $steps[] = 'The response keeps the provider shape (success, challenge_ts, hostname, error-codes), so existing handling works.';

        return $steps;
    }

    /**
     * @return list<string>
     */
    private function notes(): array
    {
        return [
            'The response fields keep the incumbent names (g-recaptcha-response and friends), so form processing code keeps working.',
            'Scopes are suggestions derived from the file path and the matched line; adjust them in the mapping table.',
            'Run this command again after the swap; a clean tree reports no findings.',
        ];
    }
}
