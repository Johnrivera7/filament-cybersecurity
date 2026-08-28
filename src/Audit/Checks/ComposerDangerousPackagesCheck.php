<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Composer\InstalledVersions;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class ComposerDangerousPackagesCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'composer.dangerous';
    }

    public function label(): string
    {
        return 'Paquetes de desarrollo peligrosos';
    }

    public function category(): string
    {
        return 'dependencies';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return $profile->isStrict();
    }

    public function run(EnvironmentProfile $profile): array
    {
        if (! class_exists(InstalledVersions::class)) {
            return [
                Finding::warn(
                    id: 'composer.dangerous.unavailable',
                    checkId: $this->id(),
                    title: 'No se pudo inspeccionar Composer',
                    description: 'Composer\\InstalledVersions no está disponible.',
                    severity: Severity::Low,
                    category: $this->category(),
                ),
            ];
        }

        /** @var list<string> $packages */
        $packages = config('filament-cybersecurity.dangerous_dev_packages', []);
        $found = [];

        foreach ($packages as $package) {
            if (InstalledVersions::isInstalled($package)) {
                $found[] = [
                    'package' => $package,
                    'version' => InstalledVersions::getPrettyVersion($package),
                ];
            }
        }

        if ($found === []) {
            return [
                Finding::pass(
                    id: 'composer.dangerous.clean',
                    checkId: $this->id(),
                    title: 'Sin paquetes de desarrollo peligrosos',
                    description: 'No aparecen herramientas de debug/dev logins en el lock de este entorno.',
                    category: $this->category(),
                ),
            ];
        }

        $list = collect($found)
            ->map(fn (array $p): string => $p['package'].'@'.$p['version'])
            ->implode(', ');

        return [
            Finding::fail(
                id: 'composer.dangerous.present',
                checkId: $this->id(),
                title: 'Paquetes de desarrollo presentes en entorno estricto',
                description: 'Detectados: '.$list,
                severity: Severity::Critical,
                remediation: 'Muévelos a require-dev, no los instales en producción (--no-dev) y desactiva developer logins.',
                category: $this->category(),
                meta: ['packages' => $found],
            ),
        ];
    }
}
