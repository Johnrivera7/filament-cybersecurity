<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Composer\InstalledVersions;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class FilamentPluginsCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'filament.plugins';
    }

    public function label(): string
    {
        return 'Plugins Filament';
    }

    public function category(): string
    {
        return 'dependencies';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return class_exists(InstalledVersions::class);
    }

    public function run(EnvironmentProfile $profile): array
    {
        $plugins = [];

        foreach (InstalledVersions::getInstalledPackages() as $package) {
            if ($this->isFilamentPlugin($package)) {
                $plugins[] = [
                    'package' => $package,
                    'version' => InstalledVersions::getPrettyVersion($package),
                ];
            }
        }

        sort($plugins);

        if ($plugins === []) {
            return [
                Finding::pass(
                    id: 'filament.plugins.none',
                    checkId: $this->id(),
                    title: 'Sin plugins Filament adicionales detectados',
                    description: 'No se encontraron paquetes filament/* o *filament* en vendor.',
                    category: $this->category(),
                ),
            ];
        }

        $dangerous = config('filament-cybersecurity.dangerous_dev_packages', []);
        $risky = [];

        foreach ($plugins as $plugin) {
            if (in_array($plugin['package'], $dangerous, true) && $profile->isStrict()) {
                $risky[] = $plugin;
            }
        }

        $findings = [
            Finding::pass(
                id: 'filament.plugins.inventory',
                checkId: $this->id(),
                title: count($plugins).' plugin(s) Filament detectados',
                description: 'Inventario de extensiones instaladas (ver detalles).',
                category: $this->category(),
                meta: ['plugins' => $plugins],
            ),
        ];

        if ($risky !== []) {
            $list = collect($risky)->map(fn (array $p): string => $p['package'].'@'.$p['version'])->implode(', ');
            $findings[] = Finding::fail(
                id: 'filament.plugins.risky',
                checkId: $this->id(),
                title: 'Plugins Filament de desarrollo en entorno estricto',
                description: 'Detectados: '.$list,
                severity: Severity::Critical,
                remediation: 'Elimina paquetes de debug/dev del deploy de producción (--no-dev).',
                category: $this->category(),
                meta: ['risky' => $risky],
            );
        }

        return $findings;
    }

    private function isFilamentPlugin(string $package): bool
    {
        if ($package === 'filament/filament') {
            return false;
        }

        return str_starts_with($package, 'filament/')
            || str_contains($package, 'filament-')
            || str_contains($package, '/filament-');
    }
}
