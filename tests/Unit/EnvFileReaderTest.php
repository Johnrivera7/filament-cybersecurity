<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Tests\Unit;

use JohnRivera7\FilamentCybersecurity\Audit\Support\EnvFileReader;
use PHPUnit\Framework\TestCase;

final class EnvFileReaderTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir().'/fcs-env-'.uniqid('', true);
        mkdir($this->tempDir);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            array_map('unlink', glob($this->tempDir.'/*') ?: []);
            rmdir($this->tempDir);
        }
    }

    public function test_keys_from_env_file(): void
    {
        $path = $this->tempDir.'/test.env';
        file_put_contents($path, <<<'ENV'
# comment
APP_KEY=secret
APP_DEBUG=true

DB_CONNECTION=mysql
ENV
        );

        $keys = EnvFileReader::keys($path);

        $this->assertSame(['APP_KEY', 'APP_DEBUG', 'DB_CONNECTION'], $keys);
    }

    public function test_keys_returns_empty_for_missing_file(): void
    {
        $this->assertSame([], EnvFileReader::keys($this->tempDir.'/missing.env'));
    }

    public function test_keys_deduplicates(): void
    {
        $path = $this->tempDir.'/dup.env';
        file_put_contents($path, "FOO=1\nFOO=2\n");

        $this->assertSame(['FOO'], EnvFileReader::keys($path));
    }
}
