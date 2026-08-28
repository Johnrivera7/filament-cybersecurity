<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Illuminate\Support\Facades\Redis;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;
use Throwable;

final class RedisUsageCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'redis.usage';
    }

    public function label(): string
    {
        return 'Redis';
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
        $uses = [];

        foreach (['cache.default' => 'cache', 'session.driver' => 'session', 'queue.default' => 'queue'] as $configKey => $label) {
            if ((string) config($configKey) === 'redis') {
                $uses[] = $label;
            }
        }

        if ($uses === []) {
            return [
                Finding::pass(
                    id: 'redis.not_used',
                    checkId: $this->id(),
                    title: 'Redis no está en uso como driver principal',
                    description: 'Cache/session/queue no apuntan a redis.',
                    category: $this->category(),
                ),
            ];
        }

        $findings = [
            Finding::pass(
                id: 'redis.configured',
                checkId: $this->id(),
                title: 'Redis en uso',
                description: 'Drivers Redis: '.implode(', ', $uses).'.',
                category: $this->category(),
                meta: [
                    'uses' => $uses,
                    'cache' => (string) config('cache.default'),
                    'session' => (string) config('session.driver'),
                    'queue' => (string) config('queue.default'),
                    'host' => (string) config('database.redis.default.host'),
                    'port' => (string) config('database.redis.default.port'),
                    'client' => (string) config('database.redis.client', 'phpredis'),
                ],
            ),
        ];

        try {
            Redis::connection()->ping();
            $findings[] = Finding::pass(
                id: 'redis.ping_ok',
                checkId: $this->id(),
                title: 'Redis responde (PING)',
                description: 'La conexión por defecto respondió correctamente.',
                category: $this->category(),
            );
        } catch (Throwable $e) {
            $findings[] = Finding::fail(
                id: 'redis.ping_fail',
                checkId: $this->id(),
                title: 'Redis no responde',
                description: 'Configurado para '.implode(', ', $uses).' pero el PING falló: '.$e->getMessage(),
                severity: $profile->isStrict() ? Severity::High : Severity::Medium,
                remediation: 'Verifica REDIS_HOST/PORT/PASSWORD y que el servicio esté arriba.',
                category: $this->category(),
            );
        }

        $client = (string) config('database.redis.client', 'phpredis');
        $password = config('database.redis.default.password');

        if ($profile->isStrict() && blank($password)) {
            $findings[] = Finding::warn(
                id: 'redis.no_auth',
                checkId: $this->id(),
                title: 'Redis sin password en config',
                description: 'En '.$profile->value.' se recomienda AUTH en Redis (o ACL) si es alcanzable en red.',
                severity: Severity::Medium,
                remediation: 'Define REDIS_PASSWORD y restringe acceso de red.',
                category: $this->category(),
                meta: ['client' => $client],
            );
        }

        return $findings;
    }
}
