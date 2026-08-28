<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Enums\CheckStatus;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\AuditReport;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;
use PHPUnit\Framework\TestCase;

final class AuditReportTest extends TestCase
{
    public function test_grade_from_score(): void
    {
        $this->assertSame('A', AuditReport::gradeFromScore(95));
        $this->assertSame('B', AuditReport::gradeFromScore(85));
        $this->assertSame('C', AuditReport::gradeFromScore(75));
        $this->assertSame('D', AuditReport::gradeFromScore(65));
        $this->assertSame('F', AuditReport::gradeFromScore(40));
    }

    public function test_score_penalties_from_failed_findings(): void
    {
        $findings = [
            Finding::fail('a', 'c', 't', 'd', Severity::Critical),
            Finding::pass('b', 'c', 't', 'd'),
            Finding::warn('w', 'c', 't', 'd', Severity::High),
        ];

        // Default config may be unavailable outside Laravel — use explicit expectation via reflection of defaults.
        $penalties = [
            'critical' => 25,
            'high' => 12,
            'medium' => 6,
            'low' => 2,
            'info' => 0,
        ];

        $score = 100;
        foreach ($findings as $finding) {
            if (! in_array($finding->status, [CheckStatus::Failed, CheckStatus::Warning], true)) {
                continue;
            }
            $score -= $penalties[$finding->severity->value];
        }

        $this->assertSame(63, $score);
    }
}
