<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit;

use Illuminate\Support\Facades\Cache;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\ApiRoutesSecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\AppDebugCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\AppKeyCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\AppUrlHttpsCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\ComposerAuditCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\ComposerDangerousPackagesCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\EnvExampleDriftCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\FilamentPluginsCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\HorizonWorkersCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\MailDriverCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\PhpVersionCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\QueueConnectionCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\RedisUsageCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\RuntimeStackCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\SensitiveRoutesCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Checks\SessionSecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\AuditReport;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;
use JohnRivera7\FilamentCybersecurity\FilamentCybersecurityPlugin;
use Throwable;

final class AuditRunner
{
    /**
     * @return list<class-string<SecurityCheck>>
     */
    public static function defaultChecks(): array
    {
        return [
            EnvExampleDriftCheck::class,
            AppDebugCheck::class,
            AppKeyCheck::class,
            AppUrlHttpsCheck::class,
            SessionSecurityCheck::class,
            MailDriverCheck::class,
            SensitiveRoutesCheck::class,
            ApiRoutesSecurityCheck::class,
            ComposerDangerousPackagesCheck::class,
            ComposerAuditCheck::class,
            FilamentPluginsCheck::class,
            RedisUsageCheck::class,
            QueueConnectionCheck::class,
            HorizonWorkersCheck::class,
            PhpVersionCheck::class,
            RuntimeStackCheck::class,
        ];
    }

    public function run(bool $fresh = false): AuditReport
    {
        $ttl = (int) config('filament-cybersecurity.cache_ttl', 300);
        $cacheKey = 'filament-cybersecurity.audit-report';

        if (! $fresh && $ttl > 0 && Cache::has($cacheKey)) {
            /** @var array<string, mixed> $cached */
            $cached = Cache::get($cacheKey);

            if (is_array($cached)) {
                return AuditReport::fromArray($cached);
            }
        }

        $report = $this->execute();

        if ($ttl > 0) {
            Cache::put($cacheKey, $report->toArray(), $ttl);
        }

        return $report;
    }

    public function execute(): AuditReport
    {
        $profile = EnvironmentProfile::resolve();
        $findings = [];

        foreach ($this->resolveChecks() as $check) {
            if (! $check->appliesTo($profile)) {
                continue;
            }

            try {
                foreach ($check->run($profile) as $finding) {
                    $findings[] = $finding;
                }
            } catch (Throwable $e) {
                $findings[] = Finding::warn(
                    id: $check->id().'.error',
                    checkId: $check->id(),
                    title: $check->label().' — error',
                    description: 'El check falló al ejecutarse: '.$e->getMessage(),
                    severity: Severity::Medium,
                    remediation: 'Revisa logs y la implementación del check.',
                    category: $check->category(),
                );
            }
        }

        usort(
            $findings,
            function (Finding $a, Finding $b): int {
                $statusOrder = [
                    'failed' => 0,
                    'warning' => 1,
                    'passed' => 2,
                    'skipped' => 3,
                ];

                $byStatus = ($statusOrder[$a->status->value] ?? 9) <=> ($statusOrder[$b->status->value] ?? 9);
                if ($byStatus !== 0) {
                    return $byStatus;
                }

                return $a->severity->sortOrder() <=> $b->severity->sortOrder();
            }
        );

        $score = AuditReport::scoreFromFindings($findings);

        return new AuditReport(
            profile: $profile,
            findings: $findings,
            score: $score,
            grade: AuditReport::gradeFromScore($score),
            ranAt: now(),
        );
    }

    /**
     * @return list<SecurityCheck>
     */
    public function resolveChecks(): array
    {
        /** @var list<class-string<SecurityCheck>> $configured */
        $configured = config('filament-cybersecurity.checks', []);

        $classes = $configured !== [] ? $configured : self::defaultChecks();

        try {
            $classes = array_values(array_unique([
                ...$classes,
                ...FilamentCybersecurityPlugin::get()->getExtraChecks(),
            ]));
        } catch (Throwable) {
            // Plugin may not be registered on the panel when running CLI-only.
        }

        $checks = [];

        foreach ($classes as $class) {
            if (! is_subclass_of($class, SecurityCheck::class)) {
                continue;
            }

            $checks[] = app($class);
        }

        return $checks;
    }
}
