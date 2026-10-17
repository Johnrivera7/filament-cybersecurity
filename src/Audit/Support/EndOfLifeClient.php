<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

final class EndOfLifeClient
{
    private const BASE_URL = 'https://endoflife.date/api/v1/products';

    /**
     * @return array<string, mixed>|null
     */
    public static function product(string $slug): ?array
    {
        $url = self::BASE_URL.'/'.rawurlencode($slug).'/';

        return HttpClient::get($url, 20);
    }

    /**
     * @return array{
     *     product: string,
     *     version: string,
     *     release: ?array<string, mixed>,
     *     is_eol: bool,
     *     is_eoas: bool,
     *     is_maintained: bool,
     *     latest_patch: ?string,
     *     behind_patch: bool,
     *     cpe: ?string,
     * }|null
     */
    public static function analyze(string $productSlug, string $version): ?array
    {
        $payload = self::product($productSlug);

        if ($payload === null || ! isset($payload['result']['releases']) || ! is_array($payload['result']['releases'])) {
            return null;
        }

        /** @var list<array<string, mixed>> $releases */
        $releases = $payload['result']['releases'];
        $release = self::matchRelease($version, $releases);

        if ($release === null) {
            return null;
        }

        $latest = is_array($release['latest'] ?? null) ? $release['latest']['name'] ?? null : null;
        $latest = is_string($latest) ? $latest : null;
        $latestNumeric = $latest !== null ? self::numericVersionPrefix($latest) : null;
        $installedNumeric = self::numericVersionPrefix($version);

        $cpe = self::extractCpe($payload);

        return [
            'product' => $productSlug,
            'version' => $version,
            'release' => $release,
            'is_eol' => (bool) ($release['isEol'] ?? false),
            'is_eoas' => (bool) ($release['isEoas'] ?? false),
            'is_maintained' => (bool) ($release['isMaintained'] ?? true),
            'latest_patch' => $latest,
            'behind_patch' => $latestNumeric !== null
                && $installedNumeric !== null
                && version_compare($installedNumeric, $latestNumeric, '<'),
            'cpe' => $cpe,
        ];
    }

    /**
     * Strip suffixes such as " CU27+GDR" so version_compare can run on dotted builds.
     */
    public static function numericVersionPrefix(string $version): ?string
    {
        if (preg_match('/^(\d+(?:\.\d+)*)/', trim($version), $matches) === 1) {
            return $matches[1];
        }

        return null;
    }

    /**
     * @param  list<array<string, mixed>>  $releases
     * @return array<string, mixed>|null
     */
    public static function matchRelease(string $version, array $releases): ?array
    {
        usort($releases, fn (array $a, array $b): int => strlen((string) ($b['name'] ?? '')) <=> strlen((string) ($a['name'] ?? '')));

        foreach ($releases as $release) {
            $name = (string) ($release['name'] ?? '');

            if ($name === '') {
                continue;
            }

            if ($version === $name || str_starts_with($version, $name.'.')) {
                return $release;
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function extractCpe(array $payload): ?string
    {
        $identifiers = $payload['result']['identifiers'] ?? null;

        if (! is_array($identifiers)) {
            return null;
        }

        foreach ($identifiers as $identifier) {
            if (! is_array($identifier)) {
                continue;
            }

            if (($identifier['type'] ?? null) === 'cpe' && is_string($identifier['id'] ?? null)) {
                return $identifier['id'];
            }
        }

        return null;
    }
}
