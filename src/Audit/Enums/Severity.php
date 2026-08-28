<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Enums;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function label(): string
    {
        $key = 'filament-cybersecurity::plugin.severity.'.$this->value;

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
            self::Critical => 'danger',
            self::High => 'warning',
            self::Medium => 'primary',
            self::Low => 'gray',
            self::Info => 'info',
        };
    }

    public function sortOrder(): int
    {
        return match ($this) {
            self::Critical => 0,
            self::High => 1,
            self::Medium => 2,
            self::Low => 3,
            self::Info => 4,
        };
    }
}
