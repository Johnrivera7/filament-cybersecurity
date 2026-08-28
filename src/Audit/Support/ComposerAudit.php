<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

final class ComposerAudit
{
    /**
     * @return array{ok: bool, error: ?string, advisories: list<array<string, mixed>>}
     */
    public static function run(): array
    {
        $process = new Process(
            ['composer', 'audit', '--format=json', '--no-interaction'],
            base_path(),
            null,
            null,
            120,
        );

        try {
            $process->mustRun();
        } catch (ProcessFailedException $e) {
            $output = $process->getOutput() ?: $process->getErrorOutput();
            $parsed = self::parseOutput($output);

            if ($parsed !== []) {
                return [
                    'ok' => false,
                    'error' => null,
                    'advisories' => $parsed,
                ];
            }

            if (self::isAbandonedOnlyResponse($output)) {
                return [
                    'ok' => true,
                    'error' => null,
                    'advisories' => [],
                ];
            }

            return [
                'ok' => false,
                'error' => $e->getMessage(),
                'advisories' => [],
            ];
        }

        $advisories = self::parseOutput($process->getOutput());

        return [
            'ok' => $advisories === [],
            'error' => null,
            'advisories' => $advisories,
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function parseOutput(string $output): array
    {
        if ($output === '') {
            return [];
        }

        try {
            /** @var array<string, mixed> $data */
            $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return [];
        }

        $items = [];

        if (isset($data['advisories']) && is_array($data['advisories'])) {
            foreach ($data['advisories'] as $package => $entries) {
                if (! is_array($entries)) {
                    continue;
                }

                foreach ($entries as $entry) {
                    if (! is_array($entry)) {
                        continue;
                    }

                    $items[] = self::normalizeAdvisory($package, $entry);
                }
            }
        }

        if (isset($data['vulnerabilities']) && is_array($data['vulnerabilities'])) {
            foreach ($data['vulnerabilities'] as $entry) {
                if (! is_array($entry)) {
                    continue;
                }

                $package = (string) ($entry['packageName'] ?? $entry['name'] ?? 'unknown');
                $items[] = self::normalizeAdvisory($package, $entry);
            }
        }

        return $items;
    }

    private static function isAbandonedOnlyResponse(string $output): bool
    {
        if ($output === '') {
            return false;
        }

        try {
            /** @var array<string, mixed> $data */
            $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return false;
        }

        $hasAdvisories = isset($data['advisories']) && is_array($data['advisories']) && $data['advisories'] !== [];
        $hasVulnerabilities = isset($data['vulnerabilities']) && is_array($data['vulnerabilities']) && $data['vulnerabilities'] !== [];
        $hasAbandoned = isset($data['abandoned']) && is_array($data['abandoned']) && $data['abandoned'] !== [];

        return ! $hasAdvisories && ! $hasVulnerabilities && $hasAbandoned;
    }

    /**
     * @param  array<string, mixed>  $entry
     * @return array<string, mixed>
     */
    private static function normalizeAdvisory(string $package, array $entry): array
    {
        return [
            'package' => $package,
            'severity' => strtolower((string) ($entry['severity'] ?? $entry['cve'] ?? 'unknown')),
            'title' => (string) ($entry['title'] ?? $entry['advisoryId'] ?? $entry['cve'] ?? 'Advisory'),
            'cve' => $entry['cve'] ?? $entry['advisoryId'] ?? null,
            'affected_versions' => $entry['affectedVersions'] ?? $entry['affected_versions'] ?? null,
            'reported_at' => $entry['reportedAt'] ?? $entry['reported_at'] ?? null,
            'link' => $entry['link'] ?? $entry['url'] ?? null,
        ];
    }
}
