<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Filament\Pages;

use BackedEnum;
use Closure;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Support\Icons\Heroicon;
use Illuminate\Contracts\Support\Htmlable;
use Illuminate\Support\Facades\Gate;
use JohnRivera7\FilamentCybersecurity\Audit\AuditRunner;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Filament\Widgets\CybersecurityScoreOverview;
use JohnRivera7\FilamentCybersecurity\FilamentCybersecurityPlugin;
use UnitEnum;

class CybersecurityDashboard extends Page
{
    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldCheck;

    protected static ?string $slug = 'cybersecurity-dashboard';

    protected string $view = 'filament-cybersecurity::filament.pages.cybersecurity-dashboard';

    public ?array $reportData = null;

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
                ->color('primary')
                ->action('rescan'),
        ];
    }

    protected function getHeaderWidgets(): array
    {
        return [
            CybersecurityScoreOverview::class,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function getReportData(): array
    {
        return $this->reportData ?? [];
    }

    protected function loadReport(AuditRunner $runner, bool $fresh = false): void
    {
        $report = $runner->run(fresh: $fresh);
        $this->reportData = $report->toArray();

        $this->dispatch('cybersecurity-report-updated', report: $this->reportData);
    }

    public function getGradeColor(): string
    {
        $grade = $this->reportData['grade'] ?? 'F';

        return match ($grade) {
            'A' => 'success',
            'B' => 'info',
            'C' => 'warning',
            'D', 'F' => 'danger',
            default => 'gray',
        };
    }

    public function severityColor(string $severity): string
    {
        return Severity::tryFrom($severity)?->color() ?? 'gray';
    }
}
