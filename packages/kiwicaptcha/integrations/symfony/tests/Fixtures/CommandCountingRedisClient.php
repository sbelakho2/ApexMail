<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Fixtures;

/**
 * A real-Redis Predis client that records every command — including the
 * raw WAIT issued through {@see \Predis\Client::executeRaw()} — so the
 * real-Redis durability tests can assert exactly when the verified
 * replica barrier runs (and how often).
 */
final class CommandCountingRedisClient extends \Predis\Client
{
    /** @var list<array{0: string, 1: list<mixed>}> every command issued, WAIT included */
    public array $commands = [];

    public function __call($commandID, $arguments)
    {
        $this->commands[] = [strtoupper((string) $commandID), $arguments];

        return parent::__call($commandID, $arguments);
    }

    public function executeRaw(array $arguments, &$error = null): mixed
    {
        $this->commands[] = [strtoupper((string) ($arguments[0] ?? '')), \array_slice($arguments, 1)];

        return parent::executeRaw($arguments, $error);
    }

    /** @return list<array{0: string, 1: list<mixed>}> the WAIT commands issued */
    public function waits(): array
    {
        return array_values(array_filter($this->commands, static fn (array $c): bool => $c[0] === 'WAIT'));
    }
}
