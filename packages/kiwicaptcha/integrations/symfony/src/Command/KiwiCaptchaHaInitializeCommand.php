<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Command;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The explicit authority bootstrap (docs/ha-authority.md): records the
 * initial authority pin(s) of the pinned-primary authority guard(s).
 *
 * The production runtime never auto-pins. A pinned_primary deployment
 * whose guard has no pin and no `ha_authority_expected` identity
 * refuses every durability-critical transition until this command has
 * run once. The command reads the serving authority identity (`INFO`
 * role + run_id) and writes the pin key write-once (`SET ... NX`) for
 * each wired authority (the storage/limiter authority and a distinct
 * risk authority). An existing pin is refused unless `--force` is
 * given, because re-pinning an authority is a deliberate operation
 * that must follow a deployment quiesce: a stale-promotion recovery
 * must never re-pin automatically. When `ha_authority_expected` is
 * configured, the pin is written to match the operator-provisioned
 * identity and a disagreement between the expected identity and the
 * connected server is refused.
 *
 * Exit status: success when every wired authority was initialized
 * (or when no pinned-primary guard is wired), failure when any
 * authority refused initialization.
 */
final class KiwiCaptchaHaInitializeCommand extends Command
{
    /**
     * @param array<string, mixed>                                    $config          the
     *        effective processed configuration (the same array the
     *        extension consumed)
     * @param array<string, PinnedPrimaryAuthorityGuard> $authorityGuards the wired
     *        pinned-primary guards keyed by authority label ("storage",
     *        "risk"), empty when ha_authority is not pinned_primary
     */
    public function __construct(
        private readonly array $config,
        private readonly array $authorityGuards,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('kiwicaptcha:ha-initialize')
            ->setDescription('Records the initial authority pin(s) for the pinned-primary authority guard(s); the production runtime never auto-pins')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Overwrite an existing pin after a deliberate authority quiesce');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $posture = (string) ($this->config['ha_authority'] ?? 'none');
        if ($posture !== 'pinned_primary' || $this->authorityGuards === []) {
            $output->writeln(sprintf(
                'ha_authority is "%s": no pinned-primary authority guard is wired, so there is nothing to initialize (see docs/ha-authority.md).',
                $posture,
            ));

            return Command::SUCCESS;
        }
        $force = (bool) $input->getOption('force');
        $failures = 0;
        foreach ($this->authorityGuards as $label => $guard) {
            $output->writeln(sprintf('Initializing the %s authority (pin key %s)...', $label, $guard->pinKey()));
            try {
                $pin = $guard->initializePin($force);
                $output->writeln(sprintf('[OK] the %s authority is pinned: %s -> %s', $label, $guard->pinKey(), $pin));
            } catch (PinnedAuthorityRefusalException $e) {
                $output->writeln(sprintf('[FAIL] %s authority: %s', $label, $e->getMessage()));
                ++$failures;
            } catch (\Throwable $e) {
                $output->writeln(sprintf('[FAIL] %s authority could not be initialized: %s', $label, $e->getMessage()));
                ++$failures;
            }
        }
        $output->writeln($failures === 0
            ? 'Summary: every wired authority is initialized.'
            : sprintf('Summary: %d authority/ies failed to initialize.', $failures));

        return $failures > 0 ? Command::FAILURE : Command::SUCCESS;
    }
}
