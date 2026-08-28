<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Filament\Pages;

use BackedEnum;
use Carbon\Carbon;
use Closure;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Support\Icons\Heroicon;
use Illuminate\Contracts\Support\Htmlable;
use Illuminate\Support\Facades\Gate;
use JohnRivera7\FilamentCybersecurity\Audit\AuditRunner;
use JohnRivera7\FilamentCybersecurity\FilamentCybersecurityPlugin;
use UnitEnum;

class CybersecurityDashboard extends Page
{
    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldCheck;

    protected static ?string $slug = 'cybersecurity-dashboard';

    protected string $view = 'filament-cybersecurity::filament.pages.cybersecurity-dashboard';

    public ?array $reportData = null;

    public string $filter = 'all';

    public static function getNavigationGroup(): string|UnitEnum|null
    {
        return FilamentCybersecurityPlugin::get()->getNavigationGroup();
    }

    public static function getNavigationLabel(): string
    {
        return FilamentCybersecurityPlugin::get()->getNavigationLabel();
    }

    public static function getNavigationIcon(): string|BackedEnum|null
    {
        return FilamentCybersecurityPlugin::get()->getNavigationIcon();
    }

    public static function getNavigationSort(): ?int
    {
        return FilamentCybersecurityPlugin::get()->getNavigationSort();
    }

    public static function canAccess(): bool
    {
        $permission = FilamentCybersecurityPlugin::get()->getPermission();

        if ($permission instanceof Closure) {
            return (bool) $permission();
        }

        if (is_string($permission) && $permission !== '') {
            $user = auth()->user();

            if ($user === null) {
                return false;
            }

            if (method_exists($user, 'can')) {
                return (bool) $user->can($permission);
            }

            return Gate::forUser($user)->allows($permission);
        }

        return auth()->check();
    }

    public function getTitle(): string|Htmlable
    {
        return __('filament-cybersecurity::plugin.page_title');
    }

    public function getSubheading(): string|Htmlable|null
    {
        return __('filament-cybersecurity::plugin.page_subheading');
    }

    public function mount(AuditRunner $runner): void
    {
        $this->loadReport($runner);
    }

    public function rescan(AuditRunner $runner): void
    {
        $this->loadReport($runner, fresh: true);

        Notification::make()
            ->title(__('filament-cybersecurity::plugin.rescanned'))
            ->success()
            ->send();
    }

    protected function getHeaderActions(): array
    {
        return [
            Action::make('rescan')
                ->label(__('filament-cybersecurity::plugin.rescan'))
                ->icon(Heroicon::OutlinedArrowPath)
                ->color('danger')
                ->action('rescan'),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function getReportData(): array
    {
        return $this->reportData ?? [];
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getFilteredFindings(): array
    {
        $findings = $this->reportData['findings'] ?? [];

        return match ($this->filter) {
            'issues' => array_values(array_filter(
                $findings,
                fn (array $f): bool => in_array($f['status'], ['failed', 'warning'], true),
            )),
            'passed' => array_values(array_filter(
                $findings,
                fn (array $f): bool => $f['status'] === 'passed',
            )),
            default => $findings,
        };
    }

    public function getScore(): int
    {
        return (int) ($this->reportData['score'] ?? 0);
    }

    public function getGrade(): string
    {
        return (string) ($this->reportData['grade'] ?? 'F');
    }

    /**
     * @return array<string, int>
     */
    public function getCounts(): array
    {
        /** @var array<string, int> $counts */
        $counts = $this->reportData['counts'] ?? [];

        return $counts;
    }

    /**
     * @return array<string, mixed>
     */
    public function getSummary(): array
    {
        /** @var array<string, mixed> $summary */
        $summary = $this->reportData['summary'] ?? [];

        return $summary;
    }

    public function hasImmediateAction(): bool
    {
        $counts = $this->getCounts();

        return ($counts['critical'] ?? 0) > 0 || ($counts['high'] ?? 0) > 0;
    }

    public function formattedRanAt(): string
    {
        $ranAt = $this->reportData['ran_at'] ?? null;

        if (! is_string($ranAt) || $ranAt === '') {
            return '—';
        }

        try {
            return Carbon::parse($ranAt)->locale(app()->getLocale())->isoFormat('LLL');
        } catch (\Throwable) {
            return $ranAt;
        }
    }

    public function findingIconClass(string $status): string
    {
        return match ($status) {
            'failed' => 'fcs-finding-icon--fail',
            'warning' => 'fcs-finding-icon--warn',
            default => 'fcs-finding-icon--pass',
        };
    }

    public function tagClass(string $status): string
    {
        return match ($status) {
            'failed' => 'fcs-tag--fail',
            'warning' => 'fcs-tag--warn',
            default => 'fcs-tag--pass',
        };
    }

    public function sevClass(string $severity, string $status): string
    {
        if ($status === 'passed') {
            return 'fcs-sev--ok';
        }

        return match ($severity) {
            'critical' => 'fcs-sev--critical',
            'high' => 'fcs-sev--high',
            'medium' => 'fcs-sev--medium',
            'low' => 'fcs-sev--low',
            default => 'fcs-sev--low',
        };
    }

    protected function loadReport(AuditRunner $runner, bool $fresh = false): void
    {
        $report = $runner->run(fresh: $fresh);
        $this->reportData = $report->toArray();
    }
}
