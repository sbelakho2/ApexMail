<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Migration;

/**
 * Scans a codebase for incumbent captcha integrations and reports every
 * finding with its file, line and matched text. The providers are the
 * five incumbent surfaces the widget shims cover: recaptcha, hcaptcha,
 * turnstile, altcha and friendly captcha.
 *
 * The scan is read-only and bounded: only files under the given root
 * with a known text extension, at most 512 KiB each, are read; build
 * and dependency directories (.git, vendor, node_modules, target, dist,
 * build, .venv, __pycache__) are skipped. A hit on a line that carries
 * a Kiwi marker (the shim attributes, the kiwi__token field, a kiwi
 * route path or the core bridge global) is discarded, so a codebase
 * that already embeds the shim produces no false positives.
 *
 * Scope suggestion: every finding's suggested scope comes from the
 * form the file appears to protect (the path and the matched line
 * carry the signals). login wins for auth flows, checkout for order
 * flows, comment for discussion flows, form is the fallback.
 *
 * @phpstan-type Finding array{file: string, line: int, text: string, provider: string, kind: string, scope: string}
 */
final class IncumbentScanner
{
    private const MAX_FILE_BYTES = 524288;

    private const SKIP_DIRS = [
        '.git', 'vendor', 'node_modules', 'target', 'dist', 'build',
        '.venv', 'venv', '__pycache__', 'cache', 'tmp',
    ];

    private const TEXT_EXTENSIONS = [
        'php', 'phtml', 'inc', 'module', 'theme', 'install', 'tpl',
        'html', 'htm', 'twig', 'vue', 'js', 'mjs', 'cjs', 'ts', 'tsx',
        'jsx', 'py', 'rb', 'java', 'kt', 'go', 'cs', 'rs', 'erb', 'eex',
        'heex', 'liquid', 'jinja', 'jinja2', 'mustache', 'hbs', 'svelte',
        'yaml', 'yml', 'json', 'env', 'ini', 'conf', 'properties', 'xml',
        'md', 'txt', 'astro',
    ];

    /**
     * The provider pattern tables. Each pattern is a named regex; kind
     * describes what the match means for the emitted config. The kinds
     * are sitekey (a public sitekey value), markup (client container
     * markup), global (the provider client global), script (the
     * provider script URL) and verify (the provider server verify URL).
     *
     * @var array<string, list<array{kind: string, pattern: string}>>
     */
    private const PROVIDER_PATTERNS = [
        'recaptcha' => [
            ['kind' => 'sitekey', 'pattern' => '/recaptcha[_\-]?site[_\-]?key\b/i'],
            ['kind' => 'sitekey', 'pattern' => '/\bRECAPTCHA_SITE_KEY\b/'],
            ['kind' => 'sitekey', 'pattern' => '/\bgr_site_key\b/i'],
            ['kind' => 'markup', 'pattern' => '/class=["\'][^"\']*g-recaptcha[^"\']*["\']/i'],
            ['kind' => 'markup', 'pattern' => '/g-recaptcha-response/i'],
            ['kind' => 'global', 'pattern' => '/\bgrecaptcha\s*\.\s*(render|execute|getResponse|reset|ready)\b/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/www\.google\.com\/recaptcha\/api\.js/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/www\.gstatic\.com\/recaptcha/i'],
            ['kind' => 'verify', 'pattern' => '/https?:\/\/(?:www\.)?google\.com\/recaptcha\/api\/siteverify/i'],
        ],
        'hcaptcha' => [
            ['kind' => 'sitekey', 'pattern' => '/hcaptcha[_\-]?site[_\-]?key\b/i'],
            ['kind' => 'sitekey', 'pattern' => '/\bHCAPTCHA_SITE_KEY\b/'],
            ['kind' => 'markup', 'pattern' => '/class=["\'][^"\']*h-captcha[^"\']*["\']/i'],
            ['kind' => 'markup', 'pattern' => '/h-captcha-response/i'],
            ['kind' => 'global', 'pattern' => '/\bhcaptcha\s*\.\s*(render|execute|getResponse|getRespKey|reset|close)\b/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/js\.hcaptcha\.com\/1\/api\.js/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/hcaptcha\.com\/1\/api\.js/i'],
            ['kind' => 'verify', 'pattern' => '/https?:\/\/api\.hcaptcha\.com\/siteverify/i'],
        ],
        'turnstile' => [
            ['kind' => 'sitekey', 'pattern' => '/turnstile[_\-]?site[_\-]?key\b/i'],
            ['kind' => 'sitekey', 'pattern' => '/\bTURNSTILE_SITE_KEY\b/'],
            ['kind' => 'markup', 'pattern' => '/class=["\'][^"\']*cf-turnstile[^"\']*["\']/i'],
            ['kind' => 'markup', 'pattern' => '/cf-turnstile-response/i'],
            ['kind' => 'global', 'pattern' => '/\bturnstile\s*\.\s*(render|execute|reset|remove|getResponse|isExpired)\b/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/challenges\.cloudflare\.com\/turnstile/i'],
            ['kind' => 'verify', 'pattern' => '/https?:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/siteverify/i'],
        ],
        'altcha' => [
            ['kind' => 'markup', 'pattern' => '/<altcha-widget[\s>]/i'],
            ['kind' => 'markup', 'pattern' => '/class=["\'][^"\']*altcha[^"\']*["\']/i'],
            ['kind' => 'sitekey', 'pattern' => '/altcha[_\-]?site[_\-]?key\b/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/altcha\.org\//i'],
            ['kind' => 'verify', 'pattern' => '/\bserververification\b/i'],
        ],
        'friendly' => [
            ['kind' => 'markup', 'pattern' => '/class=["\'][^"\']*frc-captcha[^"\']*["\']/i'],
            ['kind' => 'markup', 'pattern' => '/frc-captcha-solution/i'],
            ['kind' => 'sitekey', 'pattern' => '/friendly[_\-]?captcha[_\-]?site[_\-]?key\b/i'],
            ['kind' => 'sitekey', 'pattern' => '/\bFRC_SITEKEY\b/'],
            ['kind' => 'global', 'pattern' => '/\bfriendlyChallenge\s*\.\s*WidgetInstance\b/i'],
            ['kind' => 'script', 'pattern' => '/https?:\/\/(?:cdn|info)\.friendlycaptcha\.com\//i'],
        ],
        // The shared incumbent container attribute (every provider
        // markup copies the recaptcha convention). The provider is
        // resolved from the line context in scanFile().
        'sitekey-attr' => [
            ['kind' => 'sitekey', 'pattern' => '/\bdata-sitekey\s*=\s*["\'][^"\']+["\']/i'],
        ],
    ];

    /**
     * Kiwi marker patterns: a line carrying any of these is a shim or
     * core line, so every incumbent-shaped hit on it is a false
     * positive and is discarded.
     *
     * @var list<string>
     */
    private const KIWI_MARKERS = [
        '/data-kiwi-[\w-]+/i',
        '/kiwi__token/i',
        '/__kiwiCaptchaCore/i',
        '/\/kiwi-captcha\//i',
        '/\/kiwicaptcha\//i',
        '/kiwicaptcha[_\-]?(site[_\-]?key|secret)\b/i',
        '/window\.kiwiCaptcha\b/i',
    ];

    /** Path signals that raise a scope suggestion, strongest first. */
    private const SCOPE_SIGNALS = [
        'checkout' => '/(checkout|cart|order|woo|commerce|pay|billing)/i',
        'comment' => '/(comment|discuss|review|forum|guestbook)/i',
        'login' => '/(login|signin|sign-in|log-in|register|signup|sign-up|auth|session|user|account|member)/i',
    ];

    /**
     * @param string $root the directory to scan; must exist
     *
     * @return list<Finding> every finding, ordered by file then line
     */
    public function scan(string $root): array
    {
        $real = realpath($root);
        if ($real === false || !is_dir($real)) {
            throw new \InvalidArgumentException(sprintf('scan root is not a readable directory: %s', $root));
        }

        $findings = [];
        foreach ($this->files($real) as $file) {
            $findings = [...$findings, ...$this->scanFile($real, $file)];
        }
        usort($findings, static fn (array $a, array $b): int => [$a['file'], $a['line']] <=> [$b['file'], $b['line']]);

        return $findings;
    }

    /**
     * The distinct providers with at least one finding, in a stable
     * canonical order.
     *
     * @param list<Finding> $findings
     *
     * @return list<string>
     */
    public function providersOf(array $findings): array
    {
        $order = ['recaptcha', 'hcaptcha', 'turnstile', 'altcha', 'friendly'];
        $present = array_values(array_unique(array_map(
            static fn (array $f): string => $f['provider'],
            $findings,
        )));

        return array_values(array_intersect($order, $present));
    }

    /**
     * Extract the sitekey literal near a sitekey-shaped finding, when
     * one is present on the same line. The candidate is the first
     * quoted token that looks like a provider sitekey: alphanumeric
     * with dashes and underscores, 8 to 80 chars, and at least one
     * digit or uppercase letter. Values that resolve to a URL or a
     * common attribute name never count.
     */
    public function sitekeyLiteral(string $line): ?string
    {
        if (preg_match_all('/["\'=]([A-Za-z0-9_\-\.]{8,120})["\']/', $line, $m)) {
            foreach ($m[1] as $candidate) {
                if (preg_match('/^[A-Za-z0-9_\-]+$/', $candidate) !== 1) {
                    continue;
                }
                if (preg_match('/[0-9]/', $candidate) === 1 || preg_match('/[A-Z]/', $candidate) === 1) {
                    if (preg_match('/^(https?|\/\/|data-|class|name|id|type|style|src|href|true|false)/iD', $candidate) !== 1) {
                        return $candidate;
                    }
                }
            }
        }

        return null;
    }

    /**
     * @return list<string> absolute file paths to scan
     */
    private function files(string $real): array
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($real, \FilesystemIterator::SKIP_DOTS),
                function (\SplFileInfo $current, string $key, \RecursiveDirectoryIterator $inner): bool {
                    if ($current->isDir()) {
                        return !in_array($current->getFilename(), self::SKIP_DIRS, true);
                    }

                    return $this->isScannable($current);
                },
            ),
            \RecursiveIteratorIterator::LEAVES_ONLY,
        );

        $files = [];
        foreach ($iterator as $info) {
            $files[] = $info->getPathname();
        }
        sort($files);

        return $files;
    }

    private function isScannable(\SplFileInfo $info): bool
    {
        if (!$info->isFile() || !$info->isReadable()) {
            return false;
        }
        if ($info->getSize() > self::MAX_FILE_BYTES) {
            return false;
        }

        return $this->hasTextExtension($info->getFilename());
    }

    private function hasTextExtension(string $filename): bool
    {
        foreach (self::TEXT_EXTENSIONS as $ext) {
            if (str_ends_with($filename, '.'.$ext)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<Finding>
     */
    private function scanFile(string $root, string $file): array
    {
        $handle = @fopen($file, 'r');
        if ($handle === false) {
            return [];
        }
        $relative = ltrim(substr($file, strlen($root)), '/');
        $findings = [];
        $lineNumber = 0;
        try {
            while (($line = fgets($handle)) !== false) {
                ++$lineNumber;
                $line = rtrim($line, "\r\n");
                if ($this->isKiwiMarkerLine($line)) {
                    continue;
                }
                $seenOnLine = [];
                foreach (self::PROVIDER_PATTERNS as $provider => $patterns) {
                    foreach ($patterns as $spec) {
                        if (preg_match($spec['pattern'], $line) === 1) {
                            $resolved = $provider === 'sitekey-attr'
                                ? $this->resolveSitekeyAttrProvider($line)
                                : $provider;
                            $key = $resolved.'|'.$spec['kind'];
                            if (isset($seenOnLine[$key])) {
                                continue;
                            }
                            $seenOnLine[$key] = true;
                            $findings[] = [
                                'file' => $relative,
                                'line' => $lineNumber,
                                'text' => substr(trim($line), 0, 240),
                                'provider' => $resolved,
                                'kind' => $spec['kind'],
                                'scope' => $this->suggestScope($relative, $line),
                            ];
                        }
                    }
                }
            }
        } finally {
            fclose($handle);
        }

        return $findings;
    }

    private function isKiwiMarkerLine(string $line): bool
    {
        foreach (self::KIWI_MARKERS as $pattern) {
            if (preg_match($pattern, $line) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * The provider a bare data-sitekey attribute belongs to, read from
     * the rest of the line: the container class or the script URL names
     * the provider, and the recaptcha convention is the fallback (the
     * attribute originated there).
     */
    private function resolveSitekeyAttrProvider(string $line): string
    {
        if (preg_match('/cf-turnstile|challenges\.cloudflare/i', $line) === 1) {
            return 'turnstile';
        }
        if (preg_match('/h-captcha|hcaptcha/i', $line) === 1) {
            return 'hcaptcha';
        }
        if (preg_match('/altcha/i', $line) === 1) {
            return 'altcha';
        }
        if (preg_match('/frc-captcha|friendlycaptcha/i', $line) === 1) {
            return 'friendly';
        }

        return 'recaptcha';
    }

    private function suggestScope(string $relativePath, string $line): string
    {
        foreach (self::SCOPE_SIGNALS as $scope => $pattern) {
            if (preg_match($pattern, $relativePath) === 1) {
                return $scope;
            }
        }
        foreach (self::SCOPE_SIGNALS as $scope => $pattern) {
            if (preg_match($pattern, $line) === 1) {
                return $scope;
            }
        }

        return 'form';
    }
}
