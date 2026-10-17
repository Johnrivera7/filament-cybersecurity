<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Support\RuntimeVersionProbe;
use PHPUnit\Framework\TestCase;

final class RuntimeVersionProbeTest extends TestCase
{
    public function test_sql_server_product_version_is_used_as_is(): void
    {
        $this->assertSame(
            '16.0.1000.6',
            RuntimeVersionProbe::parseSqlServerVersion('16.0.1000.6'),
        );
    }

    public function test_sql_server_at_version_prefers_build_over_marketing_year(): void
    {
        $raw = 'Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64) '
            ."\n\tOct  8 2022 05:58:25 "
            ."\n\tCopyright (C) 2022 Microsoft Corporation"
            ."\n\tStandard Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)";

        $this->assertSame('16.0.1000.6', RuntimeVersionProbe::parseSqlServerVersion($raw));
    }

    public function test_sql_server_does_not_return_marketing_year_alone(): void
    {
        $this->assertNull(RuntimeVersionProbe::parseSqlServerVersion('Microsoft SQL Server 2022'));
    }
}
