#!/bin/sh
# check-psr4: every PHP file under the package src must sit at the path its
# declared namespace/type maps to (composer.json psr-4), and no FQCN may be
# declared in more than one file. A file is owned by the declaration mapping
# to its path; secondary declarations are tolerated, duplicates always fail.
# Exit 0 when clean, 1 on any violation. Usage: bash packages/kiwicaptcha/tools/check-psr4.sh
set -eu

TOOLS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHP_PKG=$(CDPATH= cd -- "$TOOLS_DIR/../../.." && pwd)/packages/kiwicaptcha-php

php /dev/stdin "$PHP_PKG" <<'PHP'
<?php

$pkg = $argv[1] ?? null;
if ($pkg === null || !is_dir($pkg)) {
    fwrite(STDERR, "check-psr4: package directory not found: ".($pkg ?? '<none>')."\n");
    exit(2);
}

$composer = json_decode((string) file_get_contents($pkg.'/composer.json'), true);
$psr4 = $composer['autoload']['psr-4'] ?? null;
if (!is_array($psr4)) {
    fwrite(STDERR, "check-psr4: no psr-4 autoload mapping in $pkg/composer.json\n");
    exit(2);
}

$violations = [];
$fqcnFiles = [];
$scanned = 0;

$expectedFor = static function (string $fqcn) use ($psr4): ?string {
    foreach ($psr4 as $prefix => $dir) {
        if ($fqcn !== $prefix && !str_starts_with($fqcn, $prefix)) {
            continue;
        }
        return rtrim((string) $dir, '/').'/'.str_replace('\\', '/', substr($fqcn, strlen($prefix))).'.php';
    }
    return null;
};

$checkFile = static function (string $path, array $fqcns, array $expectedList) use (&$violations, &$fqcnFiles, $pkg): void {
    $actual = substr($path, strlen($pkg) + 1);
    foreach ($fqcns as $i => $fqcn) {
        if (isset($fqcnFiles[$fqcn])) {
            $violations[] = "$fqcn is declared in both $fqcnFiles[$fqcn] and $actual";
        } else {
            $fqcnFiles[$fqcn] = $actual;
        }
        if ($expectedList[$i] === null) {
            $violations[] = "$actual declares $fqcn, which no psr-4 prefix maps";
        }
    }
    // Wrong-path placement: the file must sit where one of its declared
    // types maps (a secondary declaration in an owned file is tolerated;
    // a duplicate FQCN anywhere still fails above).
    if (!in_array($actual, $expectedList, true)) {
        $expected = implode(', ', array_unique(array_filter($expectedList)));
        $violations[] = "$actual declares ".implode(', ', $fqcns).($expected === '' ? '' : ", but its path matches none of them (psr-4 maps to $expected)");
    }
};

foreach ($psr4 as $dir) {
    $root = $pkg.'/'.rtrim((string) $dir, '/');
    if (!is_dir($root)) {
        continue;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }
        $path = $file->getPathname();
        $code = (string) file_get_contents($path);
        $code = (string) preg_replace('{/\*.*?\*/}s', '', $code);
        $code = (string) preg_replace('{//.*$}m', '', $code);
        if (!preg_match('{^\s*namespace\s+([A-Za-z_][A-Za-z0-9_\\\\]*)\s*;}m', $code, $m)) {
            continue;
        }
        $ns = $m[1];
        $decls = preg_match_all('{\b(?:(?:final|abstract|readonly)\s+)?(class|interface|trait|enum)\s+([A-Za-z_][A-Za-z0-9_]*)}', $code, $declMatches, PREG_SET_ORDER);
        if ($decls === false) {
            fwrite(STDERR, "check-psr4: internal regex error on $path\n");
            exit(2);
        }
        $fqcns = [];
        $expectedList = [];
        foreach ($declMatches as $decl) {
            $fqcn = $ns.'\\'.$decl[2];
            $fqcns[] = $fqcn;
            $expectedList[] = $expectedFor($fqcn);
        }
        if ($fqcns !== []) {
            $checkFile($path, $fqcns, $expectedList);
        }
        $scanned++;
    }
}

if ($violations !== []) {
    foreach ($violations as $v) {
        fwrite(STDERR, "check-psr4: $v\n");
    }
    fwrite(STDERR, 'check-psr4: '.count($violations)." violation(s) across $scanned file(s)\n");
    exit(1);
}

echo "check-psr4: OK ($scanned file(s), no violations)\n";
PHP
