<?php

declare(strict_types=1);

/*
 * The phpredis transport stub of the EVALSHA disambiguation tests.
 * The redis extension is not loaded on every host, and the storage's
 * phpredis branch is gated on `instanceof \Redis`. This fixture
 * therefore declares a minimal global \Redis / \RedisException pair
 * carrying the canned EVALSHA transport — only when the extension is
 * absent. The
 * namespaced marker class {@see EvalShaPhpRedisStub} exists exactly
 * when the polyfill does, so the tests can feature-detect it and skip
 * where the real class cannot be safely overridden.
 */

namespace {
    if (!\extension_loaded('redis') && !\class_exists(\Redis::class, false)) {
        // The runtime marker the namespaced block below keys on: the
        // polyfill base was declared by this file (a bare class_exists
        // there would observe the class this block just declared).
        \define('KIWICAPTCHA_TESTS_REDIS_TRANSPORT_POLYFILL', true);
        class Redis
        {
            /** Number of EVALSHA invocations. */
            public int $evalShaCalls = 0;

            /** Number of plain EVAL invocations (the re-EVAL repair path). */
            public int $evalCalls = 0;

            /** Bodies of every plain EVAL invocation (the re-EVAL repair evidence). */
            public array $evalBodies = [];

            /** @var array<string, string> sha => script body registry of SCRIPT LOAD */
            public array $scriptsBySha = [];

            /**
             * The scripted EVALSHA behavior: 'clean-false' answers a Lua
             * nil (phpredis false) with an empty last-error buffer.
             * 'noscript-exception' raises the server's NOSCRIPT error as
             * a \RedisException; 'noscript-last-error' answers a clean
             * false while the last-error buffer carries NOSCRIPT (the
             * build family that surfaces the missing script through the
             * buffer instead of an exception).
             */
            public string $evalShaBehavior = 'clean-false';

            private ?string $lastError = null;

            /** @param list<mixed> $args */
            public function script(string $subcommand, string $body): string
            {
                $sha = sha1($body);
                if (strcasecmp($subcommand, 'load') === 0) {
                    $this->scriptsBySha[$sha] = $body;
                }

                return $sha;
            }

            public function clearLastError(): bool
            {
                $this->lastError = null;

                return true;
            }

            public function getLastError(): ?string
            {
                return $this->lastError;
            }

            /** @param list<mixed> $args */
            public function evalSha(string $sha, array $args = [], int $numKeys = 0): mixed
            {
                ++$this->evalShaCalls;
                if (!isset($this->scriptsBySha[$sha])) {
                    // An unloaded sha raises the server's NOSCRIPT error,
                    // like a real Redis answering EVALSHA for a flushed
                    // script cache.
                    throw new \RedisException('NOSCRIPT No matching script. Please use EVAL.');
                }
                if ($this->evalShaBehavior === 'noscript-exception') {
                    throw new \RedisException('NOSCRIPT No matching script. Please use EVAL.');
                }
                if ($this->evalShaBehavior === 'noscript-last-error') {
                    $this->lastError = 'NOSCRIPT No matching script. Please use EVAL.';

                    return false;
                }
                $this->lastError = null;

                // A clean Lua nil reply: phpredis maps it to false.
                return false;
            }

            /** @param list<mixed> $args */
            public function eval(string $script, array $args = [], int $numKeys = 0): mixed
            {
                ++$this->evalCalls;
                $this->evalBodies[] = $script;
                $this->scriptsBySha[sha1($script)] = $script;

                // The repaired invocation answers with a non-nil reply
                // shape; the tests assert the transport, so a canned
                // array distinguishes the EVAL result from a nil.
                return ['repaired-via-eval'];
            }
        }

        class RedisException extends \Exception
        {
        }
    }
}

namespace KiwiCaptcha\Tests\Fixtures {

    if (\defined('KIWICAPTCHA_TESTS_REDIS_TRANSPORT_POLYFILL')) {
        /**
         * Feature marker + factory for the canned phpredis transport: the
         * global polyfill base with the stub identity, so tests can guard
         * with class_exists and instantiate through the fixture name.
         */
        final class EvalShaPhpRedisStub extends \Redis
        {
        }
    }
}
