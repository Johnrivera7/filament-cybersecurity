<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Filament\Widgets;

use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
use JohnRivera7\FilamentCybersecurity\Audit\AuditRunner;

class CybersecurityScoreOverview extends StatsOverviewWidget
{
    protected static bool $isLazy = false;

    protected function getStats(): array
    {
        $report = app(AuditRunner::class)->run();
        $counts = [
            'critical' => $report->countBySeverity(\JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity::Critical),
            'high' => $report->countBySeverity(\JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity::High),
            'failed' => count($report->failed()),
            'passed' => count($report->passed()),
        ];

        $gradeColor = match ($report->grade) {
            'A' => 'success',
            'B' => 'info',
            'C' => 'warning',
            default => 'danger',
        };

        return [
            Stat::make(__('filament-cybersecurity::plugin.stat_score'), $report->score.'/100')
                ->description(__('filament-cybersecurity::plugin.stat_grade', ['grade' => $report->grade]))
                ->descriptionIcon('heroicon-m-shield-check')
                ->color($gradeColor),
            Stat::make(__('filament-cybersecurity::plugin.stat_critical'), (string) $counts['critical'])
                ->description(__('filament-cybersecurity::plugin.stat_critical_help'))
                ->color($counts['critical'] > 0 ? 'danger' : 'success'),
            Stat::make(__('filament-cybersecurity::plugin.stat_high'), (string) $counts['high'])
                ->description(__('filament-cybersecurity::plugin.stat_high_help'))
                ->color($counts['high'] > 0 ? 'warning' : 'success'),
            Stat::make(__('filament-cybersecurity::plugin.stat_passed'), (string) $counts['passed'])
                ->description(__('filament-cybersecurity::plugin.stat_failed', ['count' => $counts['failed']]))
                ->color('success'),
        ];
    }
}
