<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity;

use Closure;
use Filament\Contracts\Plugin;
use Filament\Panel;
use JohnRivera7\FilamentCybersecurity\Filament\Pages\CybersecurityDashboard;
use JohnRivera7\FilamentCybersecurity\Filament\Widgets\CybersecurityScoreOverview;

class FilamentCybersecurityPlugin implements Plugin
{
    protected bool $hasDashboard = true;

    protected ?string $navigationGroup = null;

    protected ?string $navigationLabel = null;

    protected ?string $navigationIcon = null;

    protected ?int $navigationSort = null;

    protected string|Closure|null $permission = null;

    /** @var list<class-string<\JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck>> */
    protected array $extraChecks = [];

    public static function make(): static
    {
        return app(static::class);
    }

    public static function get(): static
    {
        /** @var static $plugin */
        $plugin = filament(app(static::class)->getId());

        return $plugin;
    }

    public function getId(): string
    {
        return 'filament-cybersecurity';
    }

    public function register(Panel $panel): void
    {
        if ($this->hasDashboard()) {
            $panel
                ->pages([
                    CybersecurityDashboard::class,
                ])
                ->widgets([
                    CybersecurityScoreOverview::class,
                ]);
        }
    }

    public function boot(Panel $panel): void
    {
        //
    }

    public function dashboard(bool $condition = true): static
    {
        $this->hasDashboard = $condition;

        return $this;
    }

    public function hasDashboard(): bool
    {
        return $this->hasDashboard && (bool) config('filament-cybersecurity.register_dashboard', true);
    }

    public function navigationGroup(?string $group): static
    {
        $this->navigationGroup = $group;

        return $this;
    }

    public function getNavigationGroup(): ?string
    {
        return $this->navigationGroup ?? config('filament-cybersecurity.navigation.group');
    }

    public function navigationLabel(?string $label): static
    {
        $this->navigationLabel = $label;

        return $this;
    }

    public function getNavigationLabel(): string
    {
        return $this->navigationLabel
            ?? (string) config('filament-cybersecurity.navigation.label', 'Cybersecurity Dashboard');
    }

    public function navigationIcon(?string $icon): static
    {
        $this->navigationIcon = $icon;

        return $this;
    }

    public function getNavigationIcon(): string
    {
        return $this->navigationIcon
            ?? (string) config('filament-cybersecurity.navigation.icon', 'heroicon-o-shield-check');
    }

    public function navigationSort(?int $sort): static
    {
        $this->navigationSort = $sort;

        return $this;
    }

    public function getNavigationSort(): int
    {
        return $this->navigationSort
            ?? (int) config('filament-cybersecurity.navigation.sort', 90);
    }

    public function permission(string|Closure|null $permission): static
    {
        $this->permission = $permission;

        return $this;
    }

    public function getPermission(): string|Closure|null
    {
        return $this->permission ?? config('filament-cybersecurity.permission');
    }

    /**
     * @param  class-string<\JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck>  $check
     */
    public function check(string $check): static
    {
        $this->extraChecks[] = $check;

        return $this;
    }

    /**
     * @return list<class-string<\JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck>>
     */
    public function getExtraChecks(): array
    {
        return $this->extraChecks;
    }
}
