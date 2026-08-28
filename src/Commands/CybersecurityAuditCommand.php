<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Commands;

use Illuminate\Console\Command;
use JohnRivera7\FilamentCybersecurity\Audit\AuditRunner;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\CheckStatus;

final class CybersecurityAuditCommand extends Command
{
    protected $signature = 'cybersecurity:audit
                            {--fresh : Ignore cached report}
                            {--json : Output JSON}';

    protected $description = 'Run the Filament Cybersecurity audit and print findings';

    public function handle(AuditRunner $runner): int
    {
        $report = $runner->run(fresh: (bool) $this->option('fresh'));

        if ($this->option('json')) {
            $this->line(json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

            return $this->exitCode($report->score);
        }

        $this->info("Cybersecurity score: {$report->score}/100 (grade {$report->grade}) · profile {$report->profile->value}");
        $this->newLine();

        foreach ($report->findings as $finding) {
            $prefix = match ($finding->status) {
                CheckStatus::Passed => '<fg=green>PASS</>',
                CheckStatus::Failed => '<fg=red>FAIL</>',
                CheckStatus::Warning => '<fg=yellow>WARN</>',
                CheckStatus::Skipped => '<fg=gray>SKIP</>',
            };

            $this->line("[{$prefix}] [{$finding->severity->value}] {$finding->title}");
            $this->line("  {$finding->description}");

            if ($finding->remediation) {
                $this->line("  → {$finding->remediation}");
            }
        }

        return $this->exitCode($report->score);
    }

    private function exitCode(int $score): int
    {
        return $score >= 70 ? self::SUCCESS : self::FAILURE;
    }
}
