<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class AppUrlHttpsCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'app.url_https';
    }

    public function label(): string
    {
        return 'APP_URL HTTPS';
    }

    public function category(): string
    {
        return 'environment';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return $profile->isStrict();
    }

    public function run(EnvironmentProfile $profile): array
    {
        $url = (string) config('app.url');
        $scheme = parse_url($url, PHP_URL_SCHEME);

        if ($scheme !== 'https') {
            return [
                Finding::fail(
                    id: 'app.url.insecure',
                    checkId: $this->id(),
                    title: 'APP_URL no usa HTTPS',
                    description: 'En '.$profile->value.' APP_URL debería ser https://… (actual: esquema '.($scheme ?: 'vacío').').',
                    severity: Severity::High,
                    remediation: 'Actualiza APP_URL a https y configura TrustProxies / forceScheme si hay reverse proxy.',
                    category: $this->category(),
                    meta: ['scheme' => $scheme],
                ),
            ];
        }

        return [
            Finding::pass(
                id: 'app.url.https',
                checkId: $this->id(),
                title: 'APP_URL usa HTTPS',
                description: 'La URL de la aplicación está configurada con HTTPS.',
                category: $this->category(),
            ),
        ];
    }
}
