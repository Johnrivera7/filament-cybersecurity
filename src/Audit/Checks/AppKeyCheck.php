<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class AppKeyCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'app.key';
    }

    public function label(): string
    {
        return 'APP_KEY';
    }

    public function category(): string
    {
        return 'environment';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return true;
    }

    public function run(EnvironmentProfile $profile): array
    {
        $key = (string) config('app.key');

        if ($key === '') {
            return [
                Finding::fail(
                    id: 'app.key.missing',
                    checkId: $this->id(),
                    title: 'APP_KEY ausente',
                    description: 'Sin APP_KEY no hay cifrado de cookies/sesiones ni firmas confiables.',
                    severity: Severity::Critical,
                    remediation: 'Ejecuta php artisan key:generate y asegúrate de no compartir la misma key entre entornos.',
                    category: $this->category(),
                ),
            ];
        }

        return [
            Finding::pass(
                id: 'app.key.present',
                checkId: $this->id(),
                title: 'APP_KEY configurada',
                description: 'La clave de aplicación está presente (valor no mostrado).',
                category: $this->category(),
                meta: ['length' => strlen($key)],
            ),
        ];
    }
}
