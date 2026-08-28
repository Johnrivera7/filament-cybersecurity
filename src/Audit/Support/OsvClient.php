<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

final class OsvClient
{
    private const QUERY_URL = 'https://api.osv.dev/v1/querybatch';

    /**
     * @param  list<array{name: string, version: string}>  $packages
     * @return list<array<string, mixed>>
     */
    public static function scanComposerPackages(array $packages): array
    {
        if ($packages === []) {
            return [];
        }

        $advisories = [];

        foreach (array_chunk($packages, 100) as $chunk) {
            $queries = [];

            foreach ($chunk as $package) {
                $queries[] = [
                    'package' => [
                        'name' => $package['name'],
                        'ecosystem' => 'Packagist',
                    ],
                    'version' => $package['version'],
                ];
            }

            $payload = HttpClient::postJson(self::QUERY_URL, ['queries' => $queries], 90);

            if ($payload === null || ! isset($payload['results']) || ! is_array($payload['results'])) {
                continue;
            }

            foreach ($payload['results'] as $index => $result) {
                if (! is_array($result) || ! isset($result['vulns']) || ! is_array($result['vulns'])) {
                    continue;
                }

                $packageName = $chunk[$index]['name'] ?? 'unknown';
                $packageVersion = $chunk[$index]['version'] ?? 'unknown';

                foreach ($result['vulns'] as $vuln) {
                    if (! is_array($vuln)) {
                        continue;
                    }

                    $advisories[] = self::normalizeVuln($packageName, $packageVersion, $vuln);
                }
            }
        }

        return $advisories;
    }

    /**
     * @return list<array{name: string, version: string}>
     */
    public static function packagesFromLockfile(string $path): array
    {
        if (! is_readable($path)) {
            return [];
        }

        try {
            /** @var array<string, mixed> $lock */
            $lock = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return [];
        }

        $packages = [];

        foreach (['packages', 'packages-dev'] as $section) {
            if (! isset($lock[$section]) || ! is_array($lock[$section])) {
                continue;
            }

            foreach ($lock[$section] as $package) {
                if (! is_array($package)) {
                    continue;
                }

                $name = $package['name'] ?? null;
                $version = $package['version'] ?? null;

                if (! is_string($name) || ! is_string($version)) {
                    continue;
                }

                $packages[] = [
                    'name' => $name,
                    'version' => ltrim($version, 'v'),
                ];
            }
        }

        return $packages;
    }

    /**
     * @param  array<string, mixed>  $vuln
     * @return array<string, mixed>
     */
    private static function normalizeVuln(string $package, string $version, array $vuln): array
    {
        $aliases = $vuln['aliases'] ?? [];
        $cve = null;

        if (is_array($aliases)) {
            foreach ($aliases as $alias) {
                if (is_string($alias) && str_starts_with($alias, 'CVE-')) {
                    $cve = $alias;
                    break;
                }
            }
        }

        $severity = 'unknown';

        if (isset($vuln['database_specific']) && is_array($vuln['database_specific'])) {
            $severity = strtolower((string) ($vuln['database_specific']['severity'] ?? 'unknown'));
        }

        return [
            'package' => $package,
            'installed_version' => $version,
            'severity' => $severity,
            'title' => (string) ($vuln['summary'] ?? $vuln['id'] ?? 'OSV advisory'),
            'cve' => $cve,
            'id' => (string) ($vuln['id'] ?? 'OSV'),
            'link' => 'https://osv.dev/vulnerability/'.urlencode((string) ($vuln['id'] ?? '')),
        ];
    }
}
