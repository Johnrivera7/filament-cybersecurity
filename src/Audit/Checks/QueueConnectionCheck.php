<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class QueueConnectionCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'queue.connection';
    }

    public function label(): string
    {
        return 'Workers / Queue';
    }

    public function category(): string
    {
        return 'infrastructure';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return true;
    }

    public function run(EnvironmentProfile $profile): array
    {
        $connection = (string) config('queue.default');

        if ($profile->isStrict() && $connection === 'sync') {
            return [
                Finding::fail(
                    id: 'queue.sync_in_strict',
                    checkId: $this->id(),
                    title: 'QUEUE_CONNECTION=sync en entorno estricto',
                    description: 'En staging/production los jobs deberían ir a redis/database/sqs con workers (Supervisor/Horizon).',
                    severity: Severity::High,
                    remediation: 'Configura un driver async y asegúrate de tener workers activos.',
                    category: $this->category(),
                    meta: ['connection' => $connection],
                ),
            ];
        }

        $horizonInstalled = class_exists(\Laravel\Horizon\Horizon::class);

        return [
            Finding::pass(
                id: 'queue.connection_ok',
                checkId: $this->id(),
                title: 'Conexión de cola',
                description: 'Driver: '.$connection.($horizonInstalled ? ' · Horizon detectado' : ''),
                category: $this->category(),
                meta: [
                    'connection' => $connection,
                    'horizon' => $horizonInstalled,
                ],
            ),
        ];
    }
}
