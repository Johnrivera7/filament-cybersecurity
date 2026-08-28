# Cybersecurity

<img src="https://raw.githubusercontent.com/Johnrivera7/filament-cybersecurity/main/art/banner.jpg" alt="Cybersecurity Dashboard Filament plugin" class="filament-hidden" />

<p align="center">
    <a href="https://filamentphp.com/docs/5.x/panels/installation">
        <img alt="FILAMENT 5.x" src="https://img.shields.io/badge/FILAMENT-5.x-EBB304?style=for-the-badge">
    </a>
</p>

<p align="center">
    <a href="https://packagist.org/packages/johnrivera7/filament-cybersecurity">
        <img alt="Latest Version on Packagist" src="https://img.shields.io/packagist/v/johnrivera7/filament-cybersecurity.svg?style=flat-square&label=packagist">
    </a>
    <a href="https://github.com/Johnrivera7/filament-cybersecurity/blob/main/LICENSE">
        <img alt="License" src="https://img.shields.io/packagist/l/johnrivera7/filament-cybersecurity.svg?style=flat-square">
    </a>
    <a href="https://github.com/Johnrivera7/filament-cybersecurity">
        <img alt="GitHub Stars" src="https://img.shields.io/github/stars/Johnrivera7/filament-cybersecurity?style=flat-square">
    </a>
    <a href="https://github.com/Johnrivera7/filament-cybersecurity/releases">
        <img alt="Latest release" src="https://img.shields.io/github/v/release/Johnrivera7/filament-cybersecurity?style=flat-square&label=release">
    </a>
</p>

<p align="center">
    <img alt="PHP 8.2+" src="https://img.shields.io/badge/PHP-8.2%2B-777BB4?style=flat-square&logo=php&logoColor=white">
    <img alt="Laravel 11+" src="https://img.shields.io/badge/Laravel-11%2B%20%2F%2012%2B%20%2F%2013%2B-FF2D20?style=flat-square&logo=laravel&logoColor=white">
    <img alt="Filament 5" src="https://img.shields.io/badge/Filament-5.x-FDAE4B?style=flat-square">
    <img alt="MIT" src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
</p>

**Cybersecurity Dashboard** for Filament: a read-only security posture auditor for Laravel apps. Score your environment, routes, sessions, Redis, queues/workers, PHP version and dangerous Composer packages — with remediation hints. Secrets are never shown in full.

> **Stable `^1.0` (MIT).** Install from Packagist / GitHub releases — not `@dev`.

## Features

- **Cybersecurity Dashboard** page with score (0–100) and grade A–F
- Environment checks: `APP_DEBUG`, `APP_KEY`, HTTPS `APP_URL`
- Session hardening: Secure, HttpOnly, SameSite, encrypt
- Sensitive routes without auth (Horizon, Telescope, Pulse, log-viewer, …)
- **Composer CVE audit** via `composer audit` (Packagist advisories)
- **OSV.dev** live CVE scan of `composer.lock` (no API key)
- **Stack CVE / EOL**: PHP, Laravel, Redis, MySQL/MariaDB/PostgreSQL via endoflife.date + NVD
- **API routes** without auth / throttle on POST
- **`.env` vs `.env.example`** key drift
- **Horizon workers** status in staging/production
- **Mail driver** sanity in strict profiles
- **Filament plugins** inventory
- Dangerous / debug Composer packages outside local
- Redis usage + PING + auth warning
- Queue/workers: flag `sync` in staging/production
- PHP version EOL detection
- Extensible `SecurityCheck` interface + plugin `->check(...)`
- Artisan: `php artisan cybersecurity:audit` (CI-friendly exit codes)
- ES / EN translations

## Requirements

| Stack | Versions |
| --- | --- |
| PHP | 8.2+ |
| Laravel | 11.28+ / 12+ / 13+ |
| Filament | **5.x** |

## Installation

```bash
composer require johnrivera7/filament-cybersecurity:^1.0
```

Register the plugin on your Filament panel:

```php
use JohnRivera7\FilamentCybersecurity\FilamentCybersecurityPlugin;

public function panel(Panel $panel): Panel
{
    return $panel
        // ...
        ->plugin(
            FilamentCybersecurityPlugin::make()
                ->navigationGroup('Seguridad')
                ->navigationLabel('Cybersecurity Dashboard')
                ->permission('view_cybersecurity') // optional Gate / Shield
        );
}
```

Optional config:

```bash
php artisan vendor:publish --tag="filament-cybersecurity-config"
```

## CLI / CI

```bash
php artisan cybersecurity:audit --fresh
php artisan cybersecurity:audit --json
```

Exit code is non-zero when the score is below **70**.

## Custom checks

```php
FilamentCybersecurityPlugin::make()
    ->check(\App\Security\Checks\MyCustomCheck::class);
```

Implement `JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck`.

## Filament directory images

| File | Size | Field |
| --- | --- | --- |
| [`art/banner.jpg`](art/banner.jpg) | 2560×1440 | Image (required) |
| [`art/thumbnail.jpg`](art/thumbnail.jpg) | 1920×1080 | Thumbnail |

## Roadmap

- Composer advisory / CVE surface
- API throttle & Sanctum checks
- Horizon / Supervisor worker probes
- Sister plugin: antivirus / file integrity

## License

MIT © John Rivera
