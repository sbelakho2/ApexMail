<?php

declare(strict_types=1);

/**
 * Shared provenance record for the timing tools' --json-out flag.
 *
 * The timing tools measure, print and ratchet their percentiles but
 * record nothing about the machine that produced the numbers. A CI
 * timing line therefore cannot be audited or compared against a
 * baseline measured elsewhere. This helper builds the machine-readable
 * record that --json-out writes, so every timing tool carries the same
 * envelope whatever tool produced it.
 *
 * The schema string is kiwicaptcha.perf-run/1. The envelope carries
 * the tool name, the timestamp, the command line, the baseline file
 * the ratchet consulted, the environment block and the source block.
 * A value that cannot be determined is an explicit null, never an
 * omission and never a guess.
 *
 * The environment block names the PHP version and SAPI, the OS, the
 * machine architecture, the CPU count and the CPU model. It also
 * carries total memory, the runner identity variables the environment
 * actually exposes, and the Redis target and server version when a
 * Redis was used. Credentials never enter the record. The Redis target
 * is the scheme://host:port form with any userinfo replaced, and
 * runner variables whose names look like secrets are skipped.
 *
 * The record is written whether the run passes or fails its ratchet,
 * because a failing run is the one whose provenance matters most. An
 * unwritable path is a hard error: a missing record is worse than a
 * failed run. The --json-out flag never changes what is measured,
 * because every environment probe runs after the measurements.
 */

/** The one schema string shared by the timing tools' records. */
const PERF_RECORD_SCHEMA = 'kiwicaptcha.perf-run/1';

/**
 * The Redis DSN reduced to the connection target as it appears on the
 * wire, with any userinfo replaced by a redaction marker. Returns null
 * when the DSN carries no parsable host.
 */
function perf_record_redis_target(?string $url): ?string
{
    if ($url === null || $url === '') {
        return null;
    }
    $parts = parse_url($url);
    if (!is_array($parts) || !isset($parts['host']) || !is_string($parts['host']) || $parts['host'] === '') {
        return null;
    }
    $auth = isset($parts['user']) ? '<redacted>@' : '';
    $scheme = isset($parts['scheme']) && is_string($parts['scheme']) ? $parts['scheme'] : 'redis';
    $port = isset($parts['port']) ? ':'.$parts['port'] : '';

    return $scheme.'://'.$auth.$parts['host'].$port;
}

/**
 * The Redis server version behind the DSN, or null when it cannot be
 * read. The probe opens its own short-lived client and never throws.
 */
function perf_record_redis_version(?string $url): ?string
{
    if ($url === null || $url === '' || !class_exists(\Predis\Client::class)) {
        return null;
    }
    try {
        $client = new \Predis\Client($url, ['timeout' => 2.0, 'read_write_timeout' => 2.0]);
        $info = (array) $client->info('server');
        // Predis has returned both a flat section and a server-nested
        // shape across versions; accept both.
        $section = isset($info['Server']) && is_array($info['Server']) ? $info['Server'] : $info;
        $version = $section['redis_version'] ?? null;

        return is_string($version) && $version !== '' ? $version : null;
    } catch (\Throwable) {
        return null;
    }
}

/** Whether an environment variable name belongs to the runner identity. */
function perf_record_is_runner_var(string $name): bool
{
    if (preg_match('/(TOKEN|SECRET|PASSWORD|PASSWD|PASS|KEY|CREDENTIAL|AUTH|COOKIE)/i', $name) === 1) {
        return false;
    }
    if ($name === 'CI') {
        return true;
    }
    foreach (['GITHUB_', 'RUNNER_', 'KIWI_', 'BUILDKITE_', 'GITLAB_', 'CIRCLE_', 'JENKINS_', 'TRAVIS', 'DRONE_', 'TF_BUILD', 'AZURE_', 'BITBUCKET_', 'CODEBUILD_', 'SEMAPHORE', 'TEAMCITY_', 'APPVEYOR'] as $prefix) {
        if (str_starts_with($name, $prefix)) {
            return true;
        }
    }

    return false;
}

/**
 * The runner identity variables the environment exposes, taken
 * verbatim when present and never invented. Returns null when the
 * environment exposes none of the known namespaces.
 *
 * @return array<string, string>|null
 */
function perf_record_runner_identity(): ?array
{
    $all = getenv();
    if (!is_array($all)) {
        return null;
    }
    $identity = [];
    foreach ($all as $name => $value) {
        if (!is_string($name) || !is_string($value) || $value === '') {
            continue;
        }
        if (perf_record_is_runner_var($name)) {
            $identity[$name] = $value;
        }
    }
    if ($identity === []) {
        return null;
    }
    ksort($identity);

    return $identity;
}

/** The host CPU model, best effort and platform tolerant. */
function perf_record_cpu_model(): ?string
{
    if (is_readable('/proc/cpuinfo')) {
        $cpuinfo = (string) file_get_contents('/proc/cpuinfo');
        if (preg_match('/^model name\s*:\s*(.+)$/m', $cpuinfo, $m) === 1) {
            return trim($m[1]);
        }
    }
    $brand = trim((string) @shell_exec('sysctl -n machdep.cpu.brand_string 2>/dev/null'));

    return $brand !== '' ? $brand : null;
}

/** The online CPU count, or null when it cannot be read. */
function perf_record_cpu_count(): ?int
{
    $count = (int) trim((string) @shell_exec('getconf _NPROCESSORS_ONLN 2>/dev/null'));

    return $count > 0 ? $count : null;
}

/** Total physical memory in bytes, or null when it cannot be read. */
function perf_record_memory_total_bytes(): ?int
{
    if (is_readable('/proc/meminfo')) {
        $meminfo = (string) file_get_contents('/proc/meminfo');
        if (preg_match('/^MemTotal:\s+(\d+)\s*kB/m', $meminfo, $m) === 1) {
            return (int) $m[1] * 1024;
        }
    }
    $bytes = trim((string) @shell_exec('sysctl -n hw.memsize 2>/dev/null'));
    if ($bytes !== '' && ctype_digit($bytes)) {
        return (int) $bytes;
    }

    return null;
}

/**
 * The checkout identity: the commit, and whether tracked files were
 * modified. Returns null when the tool runs outside a git work tree.
 *
 * @return array{commit: string|null, dirty: bool}|null
 */
function perf_record_source(): ?array
{
    $repo = dirname(__DIR__);
    $inside = trim((string) @shell_exec('git -C '.escapeshellarg($repo).' rev-parse --is-inside-work-tree 2>/dev/null'));
    if ($inside !== 'true') {
        return null;
    }
    $commit = trim((string) @shell_exec('git -C '.escapeshellarg($repo).' rev-parse HEAD 2>/dev/null'));
    $porcelain = trim((string) @shell_exec('git -C '.escapeshellarg($repo).' status --porcelain --untracked-files=no 2>/dev/null'));

    return [
        'commit' => preg_match('/^[0-9a-f]{40}$/', $commit) === 1 ? $commit : null,
        'dirty' => $porcelain !== '',
    ];
}

/**
 * The baseline path as consulted: resolved when the file exists, the
 * given path otherwise, null when the tool read no baseline.
 */
function perf_record_baseline_path(?string $path): ?string
{
    if ($path === null || $path === '') {
        return null;
    }
    $real = realpath($path);

    return $real !== false ? $real : $path;
}

/**
 * The environment block every record carries. The Redis block is null
 * when the run used no Redis, and every unknown value inside it is an
 * explicit null.
 *
 * @return array<string, mixed>
 */
function perf_record_environment(?string $redisUrl): array
{
    return [
        'php_version' => PHP_VERSION,
        'php_sapi' => PHP_SAPI,
        'os' => php_uname('s').' '.php_uname('r'),
        'arch' => php_uname('m'),
        'cpu_model' => perf_record_cpu_model(),
        'cpu_count' => perf_record_cpu_count(),
        'memory_total_bytes' => perf_record_memory_total_bytes(),
        'runner' => perf_record_runner_identity(),
        'redis' => $redisUrl === null ? null : [
            'target' => perf_record_redis_target($redisUrl),
            'version' => perf_record_redis_version($redisUrl),
        ],
    ];
}

/**
 * The provenance envelope common to every timing tool. The record
 * fields of the individual tool are merged after this call.
 *
 * @param list<string> $argv
 * @return array<string, mixed>
 */
function perf_record_envelope(string $tool, array $argv, ?string $baselineFile, ?string $redisUrl): array
{
    return [
        'schema' => PERF_RECORD_SCHEMA,
        'tool' => $tool,
        'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
        'command' => array_values($argv),
        'baseline_file' => perf_record_baseline_path($baselineFile),
        'environment' => perf_record_environment($redisUrl),
        'source' => perf_record_source(),
    ];
}

/**
 * One measured distribution with its ratchet verdict. The p90 and the
 * throughput key are explicit nulls when the tool does not report
 * them, so a consumer can rely on a stable leaf shape. The ratchet is
 * null when the tool applies none.
 *
 * @param array<string, mixed>|null $ratchet
 * @return array<string, mixed>
 */
function perf_record_sample(int $n, float $p50, ?float $p90, float $p95, ?int $throughput, ?array $ratchet): array
{
    return [
        'n' => $n,
        'p50_ms' => $p50,
        'p90_ms' => $p90,
        'p95_ms' => $p95,
        'throughput_per_second' => $throughput,
        'ratchet' => $ratchet,
    ];
}

/**
 * The ratchet verdict block for one p95. A missing baseline leaves the
 * baseline and the limit as explicit nulls.
 *
 * @return array{baseline_p95_ms: float|null, multiplier: float, limit_p95_ms: float|null, verdict: string}
 */
function perf_record_ratchet(?float $baseline, ?float $limit, string $verdict, float $multiplier = 3.0): array
{
    return [
        'baseline_p95_ms' => $baseline,
        'multiplier' => $multiplier,
        'limit_p95_ms' => $limit,
        'verdict' => $verdict,
    ];
}

/**
 * Write the record to the given path. A null path is a no-op, because
 * --json-out was not requested. An unwritable path is a hard error:
 * the tool reports it and exits non-zero, because a missing record is
 * worse than a failed run.
 *
 * @param array<string, mixed> $record
 */
function perf_record_write(?string $path, array $record): void
{
    if ($path === null || $path === '') {
        return;
    }
    $tool = is_string($record['tool'] ?? null) ? $record['tool'] : 'perf-record';
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0777, true) && !is_dir($dir)) {
        fwrite(STDERR, "$tool: cannot create the --json-out directory $dir\n");
        exit(1);
    }
    $json = json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false || @file_put_contents($path, $json."\n") === false) {
        fwrite(STDERR, "$tool: cannot write the --json-out record $path\n");
        exit(1);
    }
    printf("%s: retained the run record in %s\n", $tool, $path);
}
