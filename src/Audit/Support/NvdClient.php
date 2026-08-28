<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

final class NvdClient
{
    private const BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    /**
     * @return list<array{id: string, summary: string, severity: string, published: ?string, link: string}>
     */
    public static function cvesForVersion(string $vendor, string $product, string $version): array
    {
        $cpeName = sprintf(
            'cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*',
            self::escapeCpe($vendor),
            self::escapeCpe($product),
            self::escapeCpe($version),
        );

        $url = self::BASE_URL.'?'.http_build_query([
            'cpeName' => $cpeName,
            'resultsPerPage' => 2000,
        ]);

        $payload = HttpClient::get($url, 45);

        if ($payload === null || ! isset($payload['vulnerabilities']) || ! is_array($payload['vulnerabilities'])) {
            return [];
        }

        $items = [];

        foreach ($payload['vulnerabilities'] as $entry) {
            if (! is_array($entry) || ! isset($entry['cve']) || ! is_array($entry['cve'])) {
                continue;
            }

            /** @var array<string, mixed> $cve */
            $cve = $entry['cve'];

            if (! self::affectsVersion($cve, $vendor, $product, $version)) {
                continue;
            }

            $id = (string) ($cve['id'] ?? 'CVE-UNKNOWN');
            $summary = self::summary($cve);
            $severity = self::severity($cve);

            $items[$id] = [
                'id' => $id,
                'summary' => $summary,
                'severity' => $severity,
                'published' => isset($cve['published']) ? (string) $cve['published'] : null,
                'link' => 'https://nvd.nist.gov/vuln/detail/'.$id,
            ];
        }

        return array_values($items);
    }

    /**
     * @param  array<string, mixed>  $cve
     */
    private static function affectsVersion(array $cve, string $vendor, string $product, string $version): bool
    {
        $configurations = $cve['configurations'] ?? null;

        if (! is_array($configurations)) {
            return false;
        }

        foreach ($configurations as $configuration) {
            if (! is_array($configuration)) {
                continue;
            }

            $nodes = $configuration['nodes'] ?? null;

            if (! is_array($nodes)) {
                continue;
            }

            foreach ($nodes as $node) {
                if (! is_array($node)) {
                    continue;
                }

                $matches = $node['cpeMatch'] ?? null;

                if (! is_array($matches)) {
                    continue;
                }

                foreach ($matches as $match) {
                    if (! is_array($match)) {
                        continue;
                    }

                    $criteria = (string) ($match['criteria'] ?? '');

                    if ($criteria === '' || ! VersionRangeMatcher::matchesProduct($criteria, $vendor, $product)) {
                        continue;
                    }

                    if (VersionRangeMatcher::isAffected($version, $match)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $cve
     */
    private static function summary(array $cve): string
    {
        $descriptions = $cve['descriptions'] ?? [];

        if (is_array($descriptions)) {
            foreach ($descriptions as $description) {
                if (is_array($description) && ($description['lang'] ?? null) === 'en') {
                    return (string) ($description['value'] ?? 'Security vulnerability');
                }
            }
        }

        return 'Security vulnerability';
    }

    /**
     * @param  array<string, mixed>  $cve
     */
    private static function severity(array $cve): string
    {
        $metrics = $cve['metrics'] ?? null;

        if (! is_array($metrics)) {
            return 'unknown';
        }

        foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $key) {
            $metricList = $metrics[$key] ?? null;

            if (! is_array($metricList)) {
                continue;
            }

            foreach ($metricList as $metric) {
                if (! is_array($metric)) {
                    continue;
                }

                $data = $metric['cvssData'] ?? null;

                if (is_array($data) && isset($data['baseSeverity'])) {
                    return strtolower((string) $data['baseSeverity']);
                }
            }
        }

        return 'unknown';
    }

    private static function escapeCpe(string $value): string
    {
        return str_replace(':', '\\:', $value);
    }
}
