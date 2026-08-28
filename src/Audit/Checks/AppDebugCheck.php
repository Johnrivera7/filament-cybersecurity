<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class AppDebugCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'app.debug';
    }

    public function label(): string
    {
        return 'APP_DEBUG';
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
        $debug = (bool) config('app.debug');

        if ($profile->isStrict() && $debug) {
            return [
                Finding::fail(
                    id: 'app.debug.enabled',
                    checkId: $this->id(),
                    title: 'APP_DEBUG está habilitado',
                    description: 'En '.$profile->value.' el modo debug expone stack traces y datos sensibles.',
                    severity: Severity::Critical,
                    remediation: 'Define APP_DEBUG=false en el .env de este entorno y limpia config:cache.',
                    category: $this->category(),
                ),
            ];
        }

        if (! $profile->isStrict() && $debug) {
            return [
                Finding::pass(
                    id: 'app.debug.local_ok',
                    checkId: $this->id(),
                    title: 'APP_DEBUG habilitado (local)',
                    description: 'Aceptable en desarrollo local. Debe estar en false en staging/production.',
                    category: $this->category(),
                ),
            ];
        }

        return [
            Finding::pass(
                id: 'app.debug.disabled',
                checkId: $this->id(),
                title: 'APP_DEBUG deshabilitado',
                description: 'El modo debug está apagado.',
                category: $this->category(),
            ),
        ];
    }
}
