<?php

declare(strict_types=1);

/**
 * Installs the canonical risk-v1 Lua state script into vendor/protocol so
 * the vendored kiwicaptcha/kiwicaptcha-risk-php package can resolve it.
 *
 * RedisRiskStateStore resolves the script via
 * `__DIR__.'/../../../../protocol/risk-v1/risk.lua'` relative to its own
 * location inside vendor/kiwicaptcha/kiwicaptcha-risk-php/src/Storage,
 * which lands on <bundle>/vendor/protocol/risk-v1/risk.lua. Composer wipes
 * vendor on refresh, so every autoload dump re-installs the copy from the
 * bundle's own tracked protocol/risk-v1/risk.lua (a byte-identical mirror
 * of the monorepo's canonical script).
 *
 * Runs as the composer "post-autoload-dump" script; a no-op when the risk
 * package is not installed.
 */

$root = dirname(__DIR__);

if (!is_dir($root.'/vendor/kiwicaptcha/kiwicaptcha-risk-php')) {
    exit(0);
}

$src = $root.'/protocol/risk-v1/risk.lua';
$dst = $root.'/vendor/protocol/risk-v1/risk.lua';

if (!is_file($src)) {
    fwrite(STDERR, "kiwicaptcha-symfony: cannot find protocol/risk-v1/risk.lua — the risk engine requires it\n");
    exit(1);
}

if (!is_dir(dirname($dst)) && !mkdir(dirname($dst), 0777, true) && !is_dir(dirname($dst))) {
    fwrite(STDERR, "kiwicaptcha-symfony: cannot create vendor/protocol/risk-v1\n");
    exit(1);
}

if (!copy($src, $dst)) {
    fwrite(STDERR, "kiwicaptcha-symfony: cannot copy risk-v1 script to vendor/protocol/risk-v1/risk.lua\n");
    exit(1);
}

fwrite(STDOUT, "kiwicaptcha-symfony: installed risk-v1 script at vendor/protocol/risk-v1/risk.lua\n");
