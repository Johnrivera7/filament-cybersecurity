<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Enums\CheckStatus;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;
use PHPUnit\Framework\TestCase;

final class FindingTest extends TestCase
{
    public function test_fail_factory(): void
    {
        $finding = Finding::fail(
            id: 'app.debug.enabled',
            checkId: 'app.debug',
            title: 'Debug on',
            description: 'Bad',
            severity: Severity::Critical,
            remediation: 'Turn off',
            category: 'environment',
        );

        $this->assertSame(CheckStatus::Failed, $finding->status);
        $this->assertSame('critical', $finding->toArray()['severity']);
        $this->assertArrayNotHasKey('secret', $finding->toArray()['meta']);
    }
}
