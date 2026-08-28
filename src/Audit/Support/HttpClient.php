<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

final class HttpClient
{
    /**
     * @return array<string, mixed>|null
     */
    public static function get(string $url, int $timeout = 30): ?array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: application/json\r\nUser-Agent: filament-cybersecurity/1.3\r\n",
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false || $body === '') {
            return null;
        }

        return self::decode($body);
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>|null
     */
    public static function postJson(string $url, array $payload, int $timeout = 60): ?array
    {
        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nAccept: application/json\r\nUser-Agent: filament-cybersecurity/1.3\r\n",
                'content' => $json,
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false || $body === '') {
            return null;
        }

        return self::decode($body);
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function decode(string $body): ?array
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            return $decoded;
        } catch (\Throwable) {
            return null;
        }
    }
}
