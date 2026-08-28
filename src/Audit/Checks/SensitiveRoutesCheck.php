<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Illuminate\Support\Facades\Route;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class SensitiveRoutesCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'routes.sensitive';
    }

    public function label(): string
    {
        return 'Rutas sensibles';
    }

    public function category(): string
    {
        return 'routes';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return true;
    }

    public function run(EnvironmentProfile $profile): array
    {
        /** @var list<string> $patterns */
        $patterns = config('filament-cybersecurity.sensitive_route_patterns', []);

        $exposed = [];

        foreach (Route::getRoutes() as $route) {
            $name = (string) $route->getName();
            $uri = $route->uri();
            $middleware = $route->gatherMiddleware();

            $isSensitive = false;

            foreach ($patterns as $pattern) {
                if ($this->matches($uri, $pattern) || ($name !== '' && $this->matches($name, $pattern))) {
                    $isSensitive = true;
                    break;
                }
            }

            if (! $isSensitive) {
                continue;
            }

            if ($this->hasAuthMiddleware($middleware)) {
                continue;
            }

            $exposed[] = [
                'uri' => $uri,
                'name' => $name !== '' ? $name : null,
                'methods' => $route->methods(),
            ];
        }

        if ($exposed === []) {
            return [
                Finding::pass(
                    id: 'routes.sensitive.protected',
                    checkId: $this->id(),
                    title: 'Rutas sensibles protegidas o ausentes',
                    description: 'No se detectaron rutas sensibles conocidas sin middleware de autenticación.',
                    category: $this->category(),
                ),
            ];
        }

        $severity = $profile->isStrict() ? Severity::Critical : Severity::High;
        $list = collect($exposed)
            ->take(15)
            ->map(fn (array $r): string => '/'.$r['uri'])
            ->implode(', ');

        return [
            Finding::fail(
                id: 'routes.sensitive.exposed',
                checkId: $this->id(),
                title: 'Rutas sensibles sin autenticación',
                description: 'Se encontraron '.count($exposed).' ruta(s) sensibles potencialmente públicas: '.$list,
                severity: $severity,
                remediation: 'Protege Horizon/Telescope/Pulse/log-viewer con auth, Gate o desactívalos fuera de local.',
                category: $this->category(),
                meta: ['count' => count($exposed), 'samples' => array_slice($exposed, 0, 15)],
            ),
        ];
    }

    private function matches(string $value, string $pattern): bool
    {
        $regex = '/^'.str_replace('\*', '.*', preg_quote($pattern, '/')).'$/i';

        return (bool) preg_match($regex, $value);
    }

    /**
     * @param  list<string|object>  $middleware
     */
    private function hasAuthMiddleware(array $middleware): bool
    {
        $authHints = [
            'auth',
            'auth:sanctum',
            'auth:web',
            'Authenticate',
            'filament.auth',
        ];

        foreach ($middleware as $item) {
            $name = is_string($item) ? $item : $item::class;

            foreach ($authHints as $hint) {
                if (str_contains($name, $hint)) {
                    return true;
                }
            }
        }

        return false;
    }
}
