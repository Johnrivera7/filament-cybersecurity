<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Support\EndOfLifeClient;
use PHPUnit\Framework\TestCase;

final class EndOfLifeClientTest extends TestCase
{
    public function test_match_release_by_major_minor(): void
    {
        $releases = [
            ['name' => '8.4'],
            ['name' => '8.3'],
            ['name' => '8'],
        ];

        $match = EndOfLifeClient::matchRelease('8.4.23', $releases);

        $this->assertSame('8.4', $match['name'] ?? null);
    }

    public function test_match_sql_server_build_against_branch(): void
    {
        $releases = [
            ['name' => '16.0', 'label' => "2022 'Dallas'"],
            ['name' => '15.0', 'label' => "2019 'Aris/Seattle'"],
        ];

        $match = EndOfLifeClient::matchRelease('16.0.1000.6', $releases);

        $this->assertSame('16.0', $match['name'] ?? null);
    }

    public function test_numeric_version_prefix_strips_cu_suffix(): void
    {
        $this->assertSame('16.0.4305.5', EndOfLifeClient::numericVersionPrefix('16.0.4305.5 CU27+GDR'));
        $this->assertSame('16.0.1000.6', EndOfLifeClient::numericVersionPrefix('16.0.1000.6'));
    }
}
