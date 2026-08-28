<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

use JohnRivera7\FilamentCybersecurity\Audit\Enums\CheckStatus;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;

final class AuditReport
{
    /**
     * @param  list<Finding>  $findings
     */
    public function __construct(
        public readonly EnvironmentProfile $profile,
        public readonly array $findings,
        public readonly int $score,
        public readonly string $grade,
        public readonly \DateTimeInterface $ranAt,
    ) {}

    /**
     * @return list<Finding>
     */
    public function failed(): array
    {
        return array_values(array_filter(
            $this->findings,
            fn (Finding $f): bool => in_array($f->status, [CheckStatus::Failed, CheckStatus::Warning], true),
        ));
    }

    /**
     * @return list<Finding>
     */
    public function passed(): array
    {
        return array_values(array_filter(
            $this->findings,
            fn (Finding $f): bool => $f->status === CheckStatus::Passed,
        ));
    }

    public function countBySeverity(Severity $severity): int
    {
        return count(array_filter(
            $this->failed(),
            fn (Finding $f): bool => $f->severity === $severity,
        ));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'profile' => $this->profile->value,
            'score' => $this->score,
            'grade' => $this->grade,
            'ran_at' => $this->ranAt->format(\DateTimeInterface::ATOM),
            'counts' => [
                'critical' => $this->countBySeverity(Severity::Critical),
                'high' => $this->countBySeverity(Severity::High),
                'medium' => $this->countBySeverity(Severity::Medium),
                'low' => $this->countBySeverity(Severity::Low),
                'info' => $this->countBySeverity(Severity::Info),
                'passed' => count($this->passed()),
                'failed' => count($this->failed()),
                'total' => count($this->findings),
            ],
            'findings' => array_map(fn (Finding $f): array => $f->toArray(), $this->findings),
        ];
    }

    public static function gradeFromScore(int $score): string
    {
        return match (true) {
            $score >= 90 => 'A',
            $score >= 80 => 'B',
            $score >= 70 => 'C',
            $score >= 60 => 'D',
            default => 'F',
        };
    }

    /**
     * @param  list<Finding>  $findings
     */
    public static function scoreFromFindings(array $findings): int
    {
        /** @var array<string, int> $penalties */
        $penalties = config('filament-cybersecurity.score_penalties', [
            'critical' => 25,
            'high' => 12,
            'medium' => 6,
            'low' => 2,
            'info' => 0,
        ]);

        $score = 100;

        foreach ($findings as $finding) {
            if (! in_array($finding->status, [CheckStatus::Failed, CheckStatus::Warning], true)) {
                continue;
            }

            $score -= (int) ($penalties[$finding->severity->value] ?? 0);
        }

        return max(0, min(100, $score));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $findings = [];

        foreach ($data['findings'] ?? [] as $item) {
            $findings[] = new Finding(
                id: (string) $item['id'],
                checkId: (string) $item['check_id'],
                title: (string) $item['title'],
                description: (string) $item['description'],
                severity: Severity::from((string) $item['severity']),
                status: CheckStatus::from((string) $item['status']),
                remediation: $item['remediation'] ?? null,
                meta: is_array($item['meta'] ?? null) ? $item['meta'] : [],
                category: $item['category'] ?? null,
            );
        }

        return new self(
            profile: EnvironmentProfile::from((string) $data['profile']),
            findings: $findings,
            score: (int) $data['score'],
            grade: (string) $data['grade'],
            ranAt: new \DateTimeImmutable((string) $data['ran_at']),
        );
    }
}
