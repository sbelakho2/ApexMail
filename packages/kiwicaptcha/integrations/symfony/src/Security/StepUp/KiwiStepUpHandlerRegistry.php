<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

/**
 * The handler registry of the step-up plane: the name-to-handler map
 * the configuration built (the built-in reference handlers under their
 * fixed names, plus every custom handler the application registered
 * through risk.step_up.handlers.custom), with the configured default
 * handler name.
 *
 * An unknown name is a refusal (fail-closed): the registry never falls
 * back to a default when an explicit name cannot be resolved, and an
 * empty registry refuses every lookup.
 */
final class KiwiStepUpHandlerRegistry
{
    /** @param array<string, StepUpHandlerInterface> $handlers */
    public function __construct(
        private readonly array $handlers,
        private readonly string $defaultHandler,
    ) {
        foreach ($handlers as $name => $handler) {
            if (preg_match('/^[a-z0-9_]{1,64}$/D', (string) $name) !== 1) {
                throw new \InvalidArgumentException(sprintf('The step-up handler name "%s" must be 1-64 chars of [a-z0-9_]', (string) $name));
            }
            if (!$handler instanceof StepUpHandlerInterface) {
                throw new \InvalidArgumentException(sprintf('The step-up handler "%s" does not implement StepUpHandlerInterface', (string) $name));
            }
        }
        if ($defaultHandler === '' || !isset($handlers[$defaultHandler])) {
            throw new \InvalidArgumentException(sprintf('The default step-up handler "%s" is not a registered handler', $defaultHandler));
        }
    }

    /**
     * The handler of a name (the configured default when the name is
     * null or empty). Unknown names are refused, never defaulted.
     */
    public function get(?string $name): StepUpHandlerInterface
    {
        $resolved = $name === null || $name === '' ? $this->defaultHandler : $name;
        $handler = $this->handlers[$resolved] ?? null;
        if ($handler === null) {
            throw new \InvalidArgumentException(sprintf(
                'The step-up handler "%s" is not registered (registered: %s)',
                $resolved,
                $this->handlers === [] ? 'none' : implode(', ', array_keys($this->handlers)),
            ));
        }

        return $handler;
    }

    public function has(string $name): bool
    {
        return isset($this->handlers[$name]);
    }

    /** @return list<string> the registered handler names */
    public function names(): array
    {
        return array_keys($this->handlers);
    }
}
