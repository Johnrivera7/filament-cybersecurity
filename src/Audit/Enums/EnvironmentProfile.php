<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Enums;

enum EnvironmentProfile: string
{
    case Local = 'local';
    case Staging = 'staging';
    case Production = 'production';

    public static function resolve(): self
    {
        $configured = (string) config('filament-cybersecurity.profile', 'auto');

        if ($configured !== 'auto') {
            return self::tryFrom($configured) ?? self::fromApp();
        }

        return self::fromApp();
    }

    public static function fromApp(): self
    {
        if (app()->environment('production', 'prod')) {
            return self::Production;
        }

        if (app()->environment('staging', 'stage', 'preprod')) {
            return self::Staging;
        }

        return self::Local;
    }

    public function isStrict(): bool
    {
        return $this === self::Production || $this === self::Staging;
    }
}
