<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class SessionSecurityCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'session.security';
    }

    public function label(): string
    {
        return 'Sesión';
    }

    public function category(): string
    {
        return 'auth';
    }

    public function appliesTo(EnvironmentProfile $profile): bool
    {
        return true;
    }

    public function run(EnvironmentProfile $profile): array
    {
        $findings = [];

        $secure = (bool) config('session.secure');
        $httpOnly = (bool) config('session.http_only', true);
        $sameSite = (string) config('session.same_site', 'lax');
        $encrypt = (bool) config('session.encrypt');

        if ($profile->isStrict() && ! $secure) {
            $findings[] = Finding::fail(
                id: 'session.secure_missing',
                checkId: $this->id(),
                title: 'Cookie de sesión sin Secure',
                description: 'SESSION_SECURE_COOKIE debería ser true en '.$profile->value.'.',
                severity: Severity::High,
                remediation: 'Define SESSION_SECURE_COOKIE=true (o session.secure=true).',
                category: $this->category(),
            );
        } else {
            $findings[] = Finding::pass(
                id: 'session.secure_ok',
                checkId: $this->id(),
                title: 'Flag Secure de sesión',
                description: $secure
                    ? 'La cookie de sesión exige HTTPS.'
                    : 'Secure desactivado (aceptable en local).',
                category: $this->category(),
            );
        }

        if (! $httpOnly) {
            $findings[] = Finding::fail(
                id: 'session.http_only_missing',
                checkId: $this->id(),
                title: 'Cookie de sesión sin HttpOnly',
                description: 'Sin HttpOnly, JavaScript puede leer la cookie de sesión (XSS → session hijack).',
                severity: Severity::High,
                remediation: 'Asegura session.http_only=true.',
                category: $this->category(),
            );
        }

        if (! in_array(strtolower($sameSite), ['lax', 'strict'], true)) {
            $findings[] = Finding::warn(
                id: 'session.same_site_weak',
                checkId: $this->id(),
                title: 'SameSite de sesión débil o vacío',
                description: 'SESSION_SAME_SITE actual: '.($sameSite !== '' ? $sameSite : '(vacío)').'.',
                severity: Severity::Medium,
                remediation: 'Usa lax o strict salvo requisitos CSRF cross-site justificados.',
                category: $this->category(),
            );
        }

        if ($profile->isStrict() && ! $encrypt) {
            $findings[] = Finding::warn(
                id: 'session.encrypt_off',
                checkId: $this->id(),
                title: 'Sesión sin cifrado',
                description: 'SESSION_ENCRYPT=false. Recomendado true en entornos estrictos.',
                severity: Severity::Low,
                remediation: 'Define SESSION_ENCRYPT=true.',
                category: $this->category(),
            );
        }

        if ($findings === []) {
            $findings[] = Finding::pass(
                id: 'session.ok',
                checkId: $this->id(),
                title: 'Sesión configurada de forma segura',
                description: 'Secure, HttpOnly y SameSite revisados.',
                category: $this->category(),
            );
        }

        return $findings;
    }
}
