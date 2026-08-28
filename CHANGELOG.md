# Changelog

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
