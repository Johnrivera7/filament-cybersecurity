<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

final class VersionRangeMatcher
{
    /**
     * @param  array<string, mixed>  $cpeMatch
     */
    public static function isAffected(string $version, array $cpeMatch): bool
    {
        if (($cpeMatch['vulnerable'] ?? true) === false) {
            return false;
        }

        $startIncluding = isset($cpeMatch['versionStartIncluding']) ? (string) $cpeMatch['versionStartIncluding'] : null;
        $startExcluding = isset($cpeMatch['versionStartExcluding']) ? (string) $cpeMatch['versionStartExcluding'] : null;
        $endIncluding = isset($cpeMatch['versionEndIncluding']) ? (string) $cpeMatch['versionEndIncluding'] : null;
        $endExcluding = isset($cpeMatch['versionEndExcluding']) ? (string) $cpeMatch['versionEndExcluding'] : null;

        if ($startIncluding !== null && version_compare($version, $startIncluding, '<')) {
            return false;
        }

        if ($startExcluding !== null && version_compare($version, $startExcluding, '<=')) {
            return false;
        }

        if ($endIncluding !== null && version_compare($version, $endIncluding, '>')) {
            return false;
        }

        if ($endExcluding !== null && version_compare($version, $endExcluding, '>=')) {
            return false;
        }

        return $startIncluding !== null
            || $startExcluding !== null
            || $endIncluding !== null
            || $endExcluding !== null;
    }

    /**
     * @param  array<string, mixed>  $configurations
     */
    public static function matchesProduct(string $criteria, string $vendor, string $product): bool
    {
        $parts = explode(':', $criteria);

        if (count($parts) < 5) {
            return false;
        }

        return strtolower($parts[3]) === strtolower($vendor)
            && strtolower($parts[4]) === strtolower($product);
    }
}
