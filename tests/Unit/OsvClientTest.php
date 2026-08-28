<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Support\OsvClient;
use PHPUnit\Framework\TestCase;

final class OsvClientTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir().'/fcs-osv-'.uniqid('', true);
        mkdir($this->tempDir);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            array_map('unlink', glob($this->tempDir.'/*') ?: []);
            rmdir($this->tempDir);
        }
    }

    public function test_packages_from_lockfile(): void
    {
        $path = $this->tempDir.'/composer.lock';
        file_put_contents($path, <<<'JSON'
{
  "packages": [
    {"name": "laravel/framework", "version": "v13.29.0"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "11.5.56"}
  ]
}
JSON
        );

        $packages = OsvClient::packagesFromLockfile($path);

        $this->assertCount(2, $packages);
        $this->assertSame('laravel/framework', $packages[0]['name']);
        $this->assertSame('13.29.0', $packages[0]['version']);
    }
}
