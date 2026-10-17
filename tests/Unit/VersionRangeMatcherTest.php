<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Support\VersionRangeMatcher;
use PHPUnit\Framework\TestCase;

final class VersionRangeMatcherTest extends TestCase
{
    public function test_affected_within_end_excluding_range(): void
    {
        $match = [
            'vulnerable' => true,
            'versionStartIncluding' => '8.3.0',
            'versionEndExcluding' => '8.3.6',
        ];

        $this->assertTrue(VersionRangeMatcher::isAffected('8.3.5', $match));
        $this->assertFalse(VersionRangeMatcher::isAffected('8.3.6', $match));
        $this->assertFalse(VersionRangeMatcher::isAffected('8.4.23', $match));
    }

    public function test_matches_product_cpe(): void
    {
        $this->assertTrue(VersionRangeMatcher::matchesProduct(
            'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',
            'php',
            'php',
        ));
    }
}
