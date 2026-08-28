<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Composer\InstalledVersions;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class RuntimeStackCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'runtime.stack';
    }

    public function label(): string
    {
        return 'Stack runtime';
    }

    public function category(): string
    {
        return 'runtime';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return true;
    }

    public function run(EnvironmentProfile $profile): array
    {
        $laravel = app()->version();
        $filament = class_exists(InstalledVersions::class)
            ? InstalledVersions::getPrettyVersion('filament/filament')
            : null;

        $meta = [
            'php' => PHP_VERSION,
            'php_sapi' => PHP_SAPI,
            'laravel' => $laravel,
            'filament' => $filament,
            'app_env' => (string) config('app.env'),
            'app_debug' => (bool) config('app.debug'),
            'cache_driver' => (string) config('cache.default'),
            'session_driver' => (string) config('session.driver'),
            'queue_driver' => (string) config('queue.default'),
            'profile' => $profile->value,
        ];

        return [
            Finding::pass(
                id: 'runtime.stack.summary',
                checkId: $this->id(),
                title: 'Stack detectado',
                description: 'PHP '.PHP_VERSION.' · Laravel '.$laravel.($filament ? ' · Filament '.$filament : ''),
                category: $this->category(),
                meta: $meta,
            ),
        ];
    }
}
