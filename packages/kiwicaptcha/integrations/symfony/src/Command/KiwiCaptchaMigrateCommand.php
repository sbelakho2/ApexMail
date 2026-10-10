<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Command;

use BelConsulting\KiwiCaptchaBundle\Migration\IncumbentScanner;
use BelConsulting\KiwiCaptchaBundle\Migration\ShimConfigEmitter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * kiwicaptcha:migrate: scans a codebase for incumbent captcha
 * integrations (recaptcha, hcaptcha, turnstile, altcha, friendly
 * captcha) and emits the shim config the spec's Part 6.3 promises:
 * the ready-to-paste client script block, the sitekey-to-scope mapping
 * table and the server-side siteverify swap instructions. An incumbent
 * migration is a key and URL swap: the client globals, the container
 * markup and the response field names keep working under the shims,
 * and the server endpoint keeps the provider request and response
 * shape.
 *
 * Output formats: text (default, the human-readable report) and json
 * (the same information, machine-readable). --out writes the report
 * to a file; --dry-run forces stdout, so a --out path is never
 * touched. Path handling is safe by construction: the root must be an
 * existing readable directory (realpath-resolved), the scan reads
 * only bounded text files and skips dependency and build directories.
 * The --out target must be an existing directory or a writable path,
 * never a directory itself.
 */
final class KiwiCaptchaMigrateCommand extends Command
{
    private const FORMAT_TEXT = 'text';
    private const FORMAT_JSON = 'json';

    public function __construct(
        private readonly ?string $defaultPath = null,
        private readonly string $prefix = '/kiwi-captcha',
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('kiwicaptcha:migrate')
            ->setDescription('Scans a codebase for incumbent captcha keys and URLs and emits the shim config')
            ->addArgument('path', InputArgument::OPTIONAL, 'The codebase directory to scan', $this->defaultPath)
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: text or json', self::FORMAT_TEXT)
            ->addOption('out', 'o', InputOption::VALUE_REQUIRED, 'Write the report to this file instead of stdout')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Print to stdout even when --out is given');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $path = $input->getArgument('path');
        if (!\is_string($path) || $path === '') {
            $output->writeln('<error>Provide the codebase directory to scan as the path argument.</error>');

            return Command::FAILURE;
        }
        $format = (string) $input->getOption('format');
        if ($format !== self::FORMAT_TEXT && $format !== self::FORMAT_JSON) {
            $output->writeln(sprintf('<error>Unknown format "%s"; use --format=text or --format=json.</error>', $format));

            return Command::FAILURE;
        }

        $scanner = new IncumbentScanner();
        try {
            $findings = $scanner->scan($path);
        } catch (\InvalidArgumentException $e) {
            $output->writeln('<error>'.htmlspecialchars($e->getMessage(), ENT_QUOTES).'</error>');

            return Command::FAILURE;
        }

        $emitter = new ShimConfigEmitter($this->prefix);
        $document = $emitter->build($findings, realpath($path) ?: $path);
        $report = $format === self::FORMAT_JSON
            ? json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR)."\n"
            : $emitter->toText($document);

        $out = $input->getOption('out');
        $dryRun = (bool) $input->getOption('dry-run');
        if (\is_string($out) && $out !== '' && !$dryRun) {
            try {
                $this->writeOut($out, $report);
            } catch (\RuntimeException $e) {
                $output->writeln('<error>'.htmlspecialchars($e->getMessage(), ENT_QUOTES).'</error>');

                return Command::FAILURE;
            }
            $output->writeln(sprintf('Report written to %s (%d provider(s), %d finding(s)).', $out, \count($document['providers']), \count($findings)));

            return Command::SUCCESS;
        }

        $output->write($report);
        if ($dryRun && \is_string($out) && $out !== '') {
            $output->writeln(sprintf('(dry run: %s was not written)', $out));
        }

        return Command::SUCCESS;
    }

    private function writeOut(string $out, string $report): void
    {
        if (is_dir($out)) {
            throw new \RuntimeException(sprintf('the --out target is a directory: %s', $out));
        }
        $dir = dirname($out);
        if (!is_dir($dir)) {
            throw new \RuntimeException(sprintf('the --out directory does not exist: %s', $dir));
        }
        if (@file_put_contents($out, $report) === false) {
            throw new \RuntimeException(sprintf('cannot write the report to %s', $out));
        }
    }
}
