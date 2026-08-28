<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Dashboard
    |--------------------------------------------------------------------------
    */
    'register_dashboard' => true,

    'navigation' => [
        'group' => 'Security',
        'sort' => 90,
        'icon' => 'heroicon-o-shield-check',
        'label' => 'Cybersecurity Dashboard',
    ],

    /*
    |--------------------------------------------------------------------------
    | Access control
    |--------------------------------------------------------------------------
    | null  = any authenticated panel user
    | string = Gate ability / Spatie permission name (e.g. view_cybersecurity)
    | callable resolved via config is not supported; use the plugin fluent API.
    */
    'permission' => null,

    /*
    |--------------------------------------------------------------------------
    | Environment profile
    |--------------------------------------------------------------------------
    | auto     → uses app()->environment()
    | local|staging|production → force profile rules
    */
    'profile' => env('CYBERSECURITY_PROFILE', 'auto'),

    /*
    |--------------------------------------------------------------------------
    | Sensitive route patterns (unauthenticated = finding)
    |--------------------------------------------------------------------------
    */
    'sensitive_route_patterns' => [
        'horizon*',
        'telescope*',
        'pulse*',
        'log-viewer*',
        'logs*',
        '_debugbar*',
        'nova*',
        'filament-impersonate*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Dangerous packages when present outside local
    |--------------------------------------------------------------------------
    */
    'dangerous_dev_packages' => [
        'laravel/telescope',
        'barryvdh/laravel-debugbar',
        'laravel/dusk',
        'nunomaduro/collision',
        'spatie/laravel-ignition',
        'dutchcodingcompany/filament-developer-logins',
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache audit results (seconds). 0 = disabled.
    |--------------------------------------------------------------------------
    */
    'cache_ttl' => (int) env('CYBERSECURITY_CACHE_TTL', 300),

    /*
    |--------------------------------------------------------------------------
    | Checks to run (class FQCNs). Empty = built-in registry.
    |--------------------------------------------------------------------------
    */
    'checks' => [],

    /*
    |--------------------------------------------------------------------------
    | Score weights by severity (failed findings)
    |--------------------------------------------------------------------------
    */
    'score_penalties' => [
        'critical' => 25,
        'high' => 12,
        'medium' => 6,
        'low' => 2,
        'info' => 0,
    ],

];
