<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Illuminate\Support\Facades\Cache;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;
use JohnRivera7\FilamentCybersecurity\Audit\Support\OsvClient;

final class OsvDependencyCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'osv.dependencies';
    }

    public function label(): string
    {
        return 'OSV.dev (Composer CVE)';
    }

    public function category(): string
    {
        return 'dependencies';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return (bool) config('filament-cybersecurity.vulnerability_intel.enabled', true)
            && (bool) config('filament-cybersecurity.vulnerability_intel.osv_dependencies', true);
    }

    public function run(EnvironmentProfile $profile): array
    {
        $lockPath = base_path('composer.lock');
        $packages = OsvClient::packagesFromLockfile($lockPath);

        if ($packages === []) {
            return [
                Finding::warn(
                    id: 'osv.lock.missing',
                    checkId: $this->id(),
                    title: 'composer.lock no disponible para OSV',
                    description: 'No se pudo leer paquetes instalados desde composer.lock.',
                    severity: Severity::Low,
                    category: $this->category(),
                ),
            ];
        }

        $ttl = (int) config('filament-cybersecurity.vulnerability_intel.cache_ttl', 86400);
        $cacheKey = 'filament-cybersecurity.osv.'.md5_file($lockPath);

        /** @var list<array<string, mixed>> $advisories */
        $advisories = Cache::remember($cacheKey, $ttl, fn (): array => OsvClient::scanComposerPackages($packages));

        if ($advisories === []) {
            return [
                Finding::pass(
                    id: 'osv.dependencies.clean',
                    checkId: $this->id(),
                    title: 'Sin vulnerabilidades OSV en dependencias',
                    description: count($packages).' paquete(s) escaneados vía OSV.dev (Packagist).',
                    category: $this->category(),
                    meta: ['packages_scanned' => count($packages), 'source' => 'osv.dev'],
                ),
            ];
        }

        $critical = count(array_filter($advisories, fn (array $a): bool => in_array($a['severity'] ?? '', ['critical', 'high'], true)));

        return [
            Finding::fail(
                id: 'osv.dependencies.vulnerabilities',
                checkId: $this->id(),
                title: count($advisories).' vulnerabilidad(es) OSV en dependencias',
                description: collect($advisories)->take(8)->map(fn (array $a): string => ($a['package'] ?? '?').' ('.($a['severity'] ?? '?').')')->implode(', '),
                severity: $critical > 0 ? Severity::Critical : Severity::High,
                remediation: 'Actualiza paquetes afectados y vuelve a ejecutar la auditoría.',
                category: $this->category(),
                meta: [
                    'packages_scanned' => count($packages),
                    'source' => 'osv.dev',
                    'advisories' => array_slice($advisories, 0, 25),
                ],
            ),
        ];
    }
}
