<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Support\ComposerAudit;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class ComposerAuditTest extends TestCase
{
    public function test_parse_output_advisories_format(): void
    {
        $json = <<<'JSON'
{
  "advisories": {
    "vendor/pkg": [
      {
        "title": "Remote code execution",
        "cve": "CVE-2024-0001",
        "severity": "critical",
        "link": "https://example.com/advisory"
      }
    ]
  }
}
JSON;

        $advisories = $this->parseOutput($json);

        $this->assertCount(1, $advisories);
        $this->assertSame('vendor/pkg', $advisories[0]['package']);
        $this->assertSame('critical', $advisories[0]['severity']);
        $this->assertSame('CVE-2024-0001', $advisories[0]['cve']);
    }

    public function test_parse_output_vulnerabilities_format(): void
    {
        $json = <<<'JSON'
{
  "vulnerabilities": [
    {
      "packageName": "acme/lib",
      "severity": "high",
      "advisoryId": "PKSA-123",
      "title": "XSS in helper"
    }
  ]
}
JSON;

        $advisories = $this->parseOutput($json);

        $this->assertCount(1, $advisories);
        $this->assertSame('acme/lib', $advisories[0]['package']);
        $this->assertSame('high', $advisories[0]['severity']);
    }

    public function test_parse_output_invalid_json_returns_empty(): void
    {
        $this->assertSame([], $this->parseOutput('not-json'));
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function parseOutput(string $output): array
    {
        $method = new ReflectionMethod(ComposerAudit::class, 'parseOutput');
        $method->setAccessible(true);

        /** @var list<array<string, mixed>> $result */
        $result = $method->invoke(null, $output);

        return $result;
    }
}
