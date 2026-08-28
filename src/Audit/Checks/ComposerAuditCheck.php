<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\ComposerAudit;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class ComposerAuditCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'composer.audit';
    }

    public function label(): string
    {
        return 'Composer audit (CVE)';
    }

    public function category(): string
    {
        return 'dependencies';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return true;
    }

    public function run(EnvironmentProfile $profile): array
    {
        if (! (bool) config('filament-cybersecurity.composer_audit.enabled', true)) {
            return [
                Finding::pass(
                    id: 'composer.audit.disabled',
                    checkId: $this->id(),
                    title: 'Composer audit deshabilitado',
                    description: 'El escaneo CVE vía composer audit está apagado en config.',
                    category: $this->category(),
                ),
            ];
        }

        $result = ComposerAudit::run();

        if ($result['error'] !== null) {
            return [
                Finding::warn(
                    id: 'composer.audit.error',
                    checkId: $this->id(),
                    title: 'No se pudo ejecutar composer audit',
                    description: $result['error'],
                    severity: Severity::Low,
                    remediation: 'Ejecuta manualmente: composer audit. Requiere Composer 2.4+ y acceso a Packagist.',
                    category: $this->category(),
                ),
            ];
        }

        /** @var list<array<string, mixed>> $advisories */
        $advisories = $result['advisories'];

        if ($advisories === []) {
            return [
                Finding::pass(
                    id: 'composer.audit.clean',
                    checkId: $this->id(),
                    title: 'Sin advisories en composer audit',
                    description: 'No se reportaron vulnerabilidades conocidas en dependencias instaladas.',
                    category: $this->category(),
                ),
            ];
        }

        $critical = count(array_filter($advisories, fn (array $a): bool => in_array($a['severity'] ?? '', ['critical', 'high'], true)));
        $severity = $critical > 0 ? Severity::Critical : Severity::High;

        $list = collect($advisories)
            ->take(10)
            ->map(fn (array $a): string => ($a['package'] ?? '?').' ('.($a['severity'] ?? '?').')')
            ->implode(', ');

        return [
            Finding::fail(
                id: 'composer.audit.vulnerabilities',
                checkId: $this->id(),
                title: count($advisories).' vulnerabilidad(es) en dependencias',
                description: 'Composer audit reportó: '.$list,
                severity: $severity,
                remediation: 'Actualiza paquetes afectados (composer update vendor/pkg) y vuelve a correr composer audit.',
                category: $this->category(),
                meta: [
                    'count' => count($advisories),
                    'advisories' => array_slice($advisories, 0, 25),
                ],
            ),
        ];
    }
}
