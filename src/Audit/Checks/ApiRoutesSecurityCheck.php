<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use Illuminate\Support\Facades\Route;
use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class ApiRoutesSecurityCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'api.security';
    }

    public function label(): string
    {
        return 'Rutas API';
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
        $findings = [];
        $unauthenticated = [];
        $withoutThrottle = [];
        $apiRouteCount = 0;

        foreach (Route::getRoutes() as $route) {
            $uri = $route->uri();

            if (! str_starts_with($uri, 'api/') && $uri !== 'api') {
                continue;
            }

            $apiRouteCount++;
            $middleware = $route->gatherMiddleware();
            $methods = array_values(array_diff($route->methods(), ['HEAD', 'OPTIONS']));

            if ($methods === []) {
                continue;
            }

            if (! $this->hasAuthMiddleware($middleware)) {
                $unauthenticated[] = [
                    'uri' => $uri,
                    'methods' => $methods,
                    'name' => $route->getName(),
                ];
            }

            if (! $this->hasThrottle($middleware) && in_array('POST', $methods, true)) {
                $withoutThrottle[] = [
                    'uri' => $uri,
                    'methods' => $methods,
                ];
            }
        }

        if ($apiRouteCount === 0) {
            return [
                Finding::pass(
                    id: 'api.none',
                    checkId: $this->id(),
                    title: 'Sin rutas API registradas',
                    description: 'No hay rutas con prefijo api/ en esta aplicación.',
                    category: $this->category(),
                ),
            ];
        }

        if ($unauthenticated === []) {
            $findings[] = Finding::pass(
                id: 'api.auth.ok',
                checkId: $this->id(),
                title: 'Rutas API con autenticación',
                description: 'Las rutas api/* detectadas incluyen middleware de autenticación.',
                category: $this->category(),
            );
        } else {
            $list = collect($unauthenticated)->take(10)->map(fn (array $r): string => '/'.$r['uri'])->implode(', ');
            $findings[] = Finding::fail(
                id: 'api.auth.missing',
                checkId: $this->id(),
                title: 'Rutas API sin autenticación',
                description: count($unauthenticated).' ruta(s) api sin auth: '.$list,
                severity: $profile->isStrict() ? Severity::Critical : Severity::High,
                remediation: 'Protege endpoints API con auth:sanctum, auth:api o middleware equivalente.',
                category: $this->category(),
                meta: ['samples' => array_slice($unauthenticated, 0, 15)],
            );
        }

        if ($withoutThrottle !== []) {
            $findings[] = Finding::warn(
                id: 'api.throttle.missing',
                checkId: $this->id(),
                title: 'Rutas API POST sin throttle',
                description: count($withoutThrottle).' endpoint(s) POST api/* sin rate limiting detectado.',
                severity: Severity::Medium,
                remediation: 'Aplica throttle middleware o RateLimiter en bootstrap/app.php / RouteServiceProvider.',
                category: $this->category(),
                meta: ['samples' => array_slice($withoutThrottle, 0, 10)],
            );
        }

        return $findings;
    }

    /**
     * @param  list<string|object>  $middleware
     */
    private function hasAuthMiddleware(array $middleware): bool
    {
        $hints = [
            'auth',
            'sanctum',
            'Authenticate',
            'auth:sanctum',
            'auth:api',
            // Bearer de integración máquina a máquina (p. ej. VerifyMoodleEnrolApiToken).
            'ApiToken',
        ];

        $extra = config('filament-cybersecurity.api_auth_middleware_hints', []);
        if (is_array($extra)) {
            foreach ($extra as $hint) {
                if (is_string($hint) && $hint !== '') {
                    $hints[] = $hint;
                }
            }
        }

        foreach ($middleware as $item) {
            $name = is_string($item) ? $item : $item::class;

            foreach ($hints as $hint) {
                if (str_contains($name, $hint)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param  list<string|object>  $middleware
     */
    private function hasThrottle(array $middleware): bool
    {
        foreach ($middleware as $item) {
            $name = is_string($item) ? $item : $item::class;

            if (str_contains($name, 'throttle') || str_contains($name, 'Throttle')) {
                return true;
            }
        }

        return false;
    }
}
