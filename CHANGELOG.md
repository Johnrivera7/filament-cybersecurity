# Changelog

## 1.2.0 — 2026-08-28

### Added

- **Composer audit (CVE)**: runs `composer audit --format=json` and surfaces advisories in the dashboard
- **API routes security**: flags unauthenticated `api/*` routes and POST endpoints without throttle
- **`.env` drift check**: compares keys in `.env` vs `.env.example` (critical keys fail)
- **Horizon workers probe**: `horizon:status` in strict profiles (staging/production)
- **Mail driver check**: warns on `log`/`array`/`failover` in strict profiles
- **Filament plugins inventory**: lists installed Filament extensions; flags dev plugins in strict mode
- Config: `critical_env_keys`, `composer_audit.enabled`, `sensitive_route_ignore_in_local`
- Meta UI: CVE advisories table, plugins list, env key drift details
- Unit tests for `EnvFileReader` and `ComposerAudit` JSON parsing

### Changed

- Sensitive routes: debug tooling (`_debugbar*`, impersonate leave) ignored in **local** profile
- Default check registry expanded (16 built-in checks)

## 1.1.0 — 2026-08-28

### Added

- Redesigned dashboard UI: circular score donut, severity stats, alert banner (matches marketing art)
- Light/dark theme via CSS variables (red + black security palette)
- Finding filters: all / open / passed
- Expandable technical meta (routes table, Composer packages, config keys)
- Runtime stack summary (PHP, Laravel, Filament, drivers)
- `RuntimeStackCheck` and richer Redis connection meta

### Changed

- Unified hero panel replaces duplicate header stats widget
- Plugin registers dashboard CSS on the Filament panel

## 1.0.0 — 2026-08-28

### Added

- Stable first release of **Cybersecurity Dashboard** for Filament 5
- Built-in checks: debug, app key, HTTPS, session, sensitive routes, dangerous packages, Redis, queue, PHP version
- Score 0–100 / grade A–F, Filament page + stats widgets
- `cybersecurity:audit` Artisan command (`--fresh`, `--json`)
- ES/EN translations
- Filament directory art (`art/banner.jpg`, `art/thumbnail.jpg`) — red & black
