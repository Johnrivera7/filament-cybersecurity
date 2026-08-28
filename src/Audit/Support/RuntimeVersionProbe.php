<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use Throwable;

final class RuntimeVersionProbe
{
    /**
     * @return list<array{
     *     key: string,
     *     label: string,
     *     version: string,
     *     eol_product: string,
     *     nvd?: array{vendor: string, product: string}|null
     * }>
     */
    public static function components(): array
    {
        $components = [
            [
                'key' => 'php',
                'label' => 'PHP',
                'version' => PHP_VERSION,
                'eol_product' => 'php',
                'nvd' => ['vendor' => 'php', 'product' => 'php'],
            ],
            [
                'key' => 'laravel',
                'label' => 'Laravel',
                'version' => self::laravelVersion() ?? 'unknown',
                'eol_product' => 'laravel',
                'nvd' => null,
            ],
        ];

        if ($redis = self::redisVersion()) {
            $components[] = [
                'key' => 'redis',
                'label' => 'Redis',
                'version' => $redis,
                'eol_product' => 'redis',
                'nvd' => ['vendor' => 'redis', 'product' => 'redis'],
            ];
        }

        if ($database = self::databaseVersion()) {
            $components[] = $database;
        }

        return $components;
    }

    private static function laravelVersion(): ?string
    {
        try {
            return app()->version();
        } catch (Throwable) {
            return null;
        }
    }

    private static function redisVersion(): ?string
    {
        if (! class_exists(Redis::class)) {
            return null;
        }

        $usesRedis = in_array('redis', [
            (string) config('cache.default'),
            (string) config('session.driver'),
            (string) config('queue.default'),
        ], true);

        if (! $usesRedis) {
            return null;
        }

        try {
            $info = Redis::connection()->info();
            $version = is_array($info) ? ($info['redis_version'] ?? null) : null;

            return is_string($version) && $version !== '' ? $version : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array{
     *     key: string,
     *     label: string,
     *     version: string,
     *     eol_product: string,
     *     nvd?: array{vendor: string, product: string}|null
     * }|null
     */
    private static function databaseVersion(): ?array
    {
        $driver = (string) config('database.default');

        if ($driver === 'sqlite') {
            return null;
        }

        $map = [
            'mysql' => ['label' => 'MySQL', 'eol' => 'mysql', 'vendor' => 'oracle', 'product' => 'mysql'],
            'mariadb' => ['label' => 'MariaDB', 'eol' => 'mariadb', 'vendor' => 'mariadb', 'product' => 'mariadb'],
            'pgsql' => ['label' => 'PostgreSQL', 'eol' => 'postgresql', 'vendor' => 'postgresql', 'product' => 'postgresql'],
            'sqlsrv' => ['label' => 'SQL Server', 'eol' => 'mssqlserver', 'vendor' => 'microsoft', 'product' => 'sql_server'],
        ];

        if (! isset($map[$driver])) {
            return null;
        }

        try {
            $version = match ($driver) {
                'pgsql' => (string) DB::scalar('SELECT version()'),
                'sqlsrv' => (string) DB::scalar('SELECT @@VERSION'),
                default => (string) DB::scalar('SELECT VERSION()'),
            };
        } catch (Throwable) {
            return null;
        }

        $parsed = self::parseDatabaseVersion($version, $driver);

        if ($parsed === null) {
            return null;
        }

        return [
            'key' => $driver,
            'label' => $map[$driver]['label'],
            'version' => $parsed,
            'eol_product' => $map[$driver]['eol'],
            'nvd' => [
                'vendor' => $map[$driver]['vendor'],
                'product' => $map[$driver]['product'],
            ],
        ];
    }

    private static function parseDatabaseVersion(string $raw, string $driver): ?string
    {
        if ($driver === 'pgsql') {
            if (preg_match('/PostgreSQL\s+([\d.]+)/i', $raw, $matches) === 1) {
                return $matches[1];
            }
        }

        if ($driver === 'sqlsrv') {
            if (preg_match('/Microsoft SQL Server\s+([\d.]+)/i', $raw, $matches) === 1) {
                return $matches[1];
            }
        }

        if (preg_match('/([\d]+\.[\d]+(?:\.[\d]+)?)/', $raw, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }
}
