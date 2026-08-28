<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\EnvFileReader;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class EnvExampleDriftCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'env.example_drift';
    }

    public function label(): string
    {
        return '.env vs .env.example';
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
        $envPath = base_path('.env');
        $examplePath = base_path('.env.example');

        if (! is_readable($examplePath)) {
            return [
                Finding::warn(
                    id: 'env.example.missing',
                    checkId: $this->id(),
                    title: '.env.example no encontrado',
                    description: 'No hay plantilla .env.example para comparar claves.',
                    severity: Severity::Low,
                    category: $this->category(),
                ),
            ];
        }

        $envKeys = EnvFileReader::keys($envPath);
        $exampleKeys = EnvFileReader::keys($examplePath);

        $missingInEnv = array_values(array_diff($exampleKeys, $envKeys));
        $extraInEnv = array_values(array_diff($envKeys, $exampleKeys));

        /** @var list<string> $critical */
        $critical = config('filament-cybersecurity.critical_env_keys', [
            'APP_KEY', 'APP_ENV', 'APP_DEBUG', 'APP_URL',
            'DB_CONNECTION', 'SESSION_DRIVER', 'QUEUE_CONNECTION',
        ]);

        $missingCritical = array_values(array_intersect($missingInEnv, $critical));

        if ($missingCritical !== []) {
            return [
                Finding::fail(
                    id: 'env.critical.missing',
                    checkId: $this->id(),
                    title: 'Claves críticas ausentes en .env',
                    description: 'Faltan en .env respecto a .env.example: '.implode(', ', $missingCritical),
                    severity: Severity::High,
                    remediation: 'Copia las claves desde .env.example y configura valores seguros.',
                    category: $this->category(),
                    meta: [
                        'missing_critical' => $missingCritical,
                        'missing_in_env' => array_slice($missingInEnv, 0, 30),
                        'extra_in_env' => array_slice($extraInEnv, 0, 30),
                    ],
                ),
            ];
        }

        if ($missingInEnv !== [] || $extraInEnv !== []) {
            return [
                Finding::warn(
                    id: 'env.drift',
                    checkId: $this->id(),
                    title: 'Deriva entre .env y .env.example',
                    description: sprintf(
                        '%d clave(s) en example no están en .env · %d extra(s) en .env',
                        count($missingInEnv),
                        count($extraInEnv),
                    ),
                    severity: Severity::Medium,
                    remediation: 'Sincroniza .env con .env.example (sin commitear secretos).',
                    category: $this->category(),
                    meta: [
                        'missing_in_env' => array_slice($missingInEnv, 0, 40),
                        'extra_in_env' => array_slice($extraInEnv, 0, 40),
                    ],
                ),
            ];
        }

        return [
            Finding::pass(
                id: 'env.synced',
                checkId: $this->id(),
                title: '.env alineado con .env.example',
                description: 'Las claves de .env coinciden con la plantilla .env.example.',
                category: $this->category(),
                meta: ['keys_count' => count($envKeys)],
            ),
        ];
    }
}
