<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class PhpVersionCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'php.version';
    }

    public function label(): string
    {
        return 'Versión PHP';
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
        $version = PHP_VERSION;
        $id = PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;

        // Branches past community active support as of 2026 — informativo / endurecible.
        $eol = [
            '8.0',
            '8.1',
            '8.2',
        ];

        if (in_array($id, $eol, true)) {
            return [
                Finding::fail(
                    id: 'php.version.eol',
                    checkId: $this->id(),
                    title: 'PHP fuera de soporte activo',
                    description: "PHP {$version} ({$id}) ya no recibe parches de seguridad de forma regular.",
                    severity: $profile->isStrict() ? Severity::High : Severity::Medium,
                    remediation: 'Actualiza a PHP 8.3 o 8.4 LTS de tu stack y vuelve a correr composer/tests.',
                    category: $this->category(),
                    meta: ['version' => $version, 'branch' => $id],
                ),
            ];
        }

        return [
            Finding::pass(
                id: 'php.version.ok',
                checkId: $this->id(),
                title: 'Versión PHP aceptable',
                description: "Ejecutando PHP {$version}.",
                category: $this->category(),
                meta: ['version' => $version],
            ),
        ];
    }
}
