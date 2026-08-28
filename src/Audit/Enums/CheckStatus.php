<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Enums;

enum CheckStatus: string
{
    case Passed = 'passed';
    case Failed = 'failed';
    case Skipped = 'skipped';
    case Warning = 'warning';

    public function label(): string
    {
        $key = 'filament-cybersecurity::plugin.status.'.$this->value;

        if (function_exists('trans') && app()->bound('translator')) {
            $translated = trans($key);

            if ($translated !== $key) {
                return $translated;
            }
        }

        return ucfirst($this->value);
    }

    public function color(): string
    {
        return match ($this) {
            self::Passed => 'success',
            self::Failed => 'danger',
            self::Skipped => 'gray',
            self::Warning => 'warning',
        };
    }
}
