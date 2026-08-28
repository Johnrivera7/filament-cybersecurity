<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

use Composer\InstalledVersions;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;

final class ReportSummary
{
    /**
     * @return array<string, mixed>
     */
    public static function build(EnvironmentProfile $profile): array
    {
        $filament = null;

        if (class_exists(InstalledVersions::class)) {
            try {
                $filament = InstalledVersions::getPrettyVersion('filament/filament');
            } catch (\Throwable) {
                $filament = null;
            }
        }

        return [
            'php' => PHP_VERSION,
            'php_sapi' => PHP_SAPI,
            'laravel' => app()->version(),
            'filament' => $filament,
            'app_env' => (string) config('app.env'),
            'app_debug' => (bool) config('app.debug'),
            'cache_driver' => (string) config('cache.default'),
            'session_driver' => (string) config('session.driver'),
            'queue_driver' => (string) config('queue.default'),
            'profile' => $profile->value,
        ];
    }
}
