<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity;

use JohnRivera7\FilamentCybersecurity\Commands\CybersecurityAuditCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class FilamentCybersecurityServiceProvider extends PackageServiceProvider
{
    public static string $name = 'filament-cybersecurity';

    public static string $viewNamespace = 'filament-cybersecurity';

    public function configurePackage(Package $package): void
    {
        $package
            ->name(static::$name)
            ->hasConfigFile()
            ->hasViews()
            ->hasTranslations()
            ->hasCommand(CybersecurityAuditCommand::class);
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(Audit\AuditRunner::class);
    }
}
