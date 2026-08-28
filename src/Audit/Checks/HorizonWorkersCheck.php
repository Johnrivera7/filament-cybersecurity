<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;
use Laravel\Horizon\Horizon;
use Symfony\Component\Process\Process;

final class HorizonWorkersCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'horizon.workers';
    }

    public function label(): string
    {
        return 'Horizon / workers';
    }

    public function category(): string
    {
        return 'infrastructure';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return class_exists(Horizon::class);
    }

    public function run(EnvironmentProfile $profile): array
    {
        $findings = [];

        $findings[] = Finding::pass(
            id: 'horizon.installed',
            checkId: $this->id(),
            title: 'Laravel Horizon instalado',
            description: 'Horizon está presente en el proyecto.',
            category: $this->category(),
        );

        if ($profile->isStrict()) {
            $process = new Process(
                [PHP_BINARY, 'artisan', 'horizon:status'],
                base_path(),
                null,
                null,
                30,
            );

            $process->run();

            if ($process->isSuccessful() && str_contains(strtolower($process->getOutput()), 'running')) {
                $findings[] = Finding::pass(
                    id: 'horizon.running',
                    checkId: $this->id(),
                    title: 'Horizon reporta workers activos',
                    description: 'horizon:status indica que el supervisor está corriendo.',
                    category: $this->category(),
                );
            } else {
                $findings[] = Finding::fail(
                    id: 'horizon.not_running',
                    checkId: $this->id(),
                    title: 'Horizon no está corriendo',
                    description: 'En '.$profile->value.' se esperan workers Horizon activos (Supervisor/systemd).',
                    severity: Severity::High,
                    remediation: 'Inicia Horizon: php artisan horizon o configura Supervisor. Verifica horizon:status.',
                    category: $this->category(),
                    meta: [
                        'exit_code' => $process->getExitCode(),
                        'output' => trim($process->getOutput().$process->getErrorOutput()),
                    ],
                );
            }
        }

        return $findings;
    }
}
