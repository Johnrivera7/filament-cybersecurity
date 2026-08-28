<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Checks;

use JohnRivera7\FilamentCybersecurity\Audit\Contracts\SecurityCheck;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

final class MailDriverCheck implements SecurityCheck
{
    public function id(): string
    {
        return 'mail.driver';
    }

    public function label(): string
    {
        return 'Mail driver';
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
        $driver = (string) config('mail.default');
        $unsafe = ['log', 'array', 'failover'];

        if (in_array($driver, $unsafe, true)) {
            return [
                Finding::fail(
                    id: 'mail.driver.unsafe',
                    checkId: $this->id(),
                    title: 'Mail driver inseguro en entorno estricto',
                    description: 'MAIL_MAILER / mail.default = '.$driver.' (no apto para producción real).',
                    severity: Severity::Medium,
                    remediation: 'Usa smtp, ses, postmark u otro driver transaccional en staging/production.',
                    category: $this->category(),
                    meta: ['driver' => $driver],
                ),
            ];
        }

        return [
            Finding::pass(
                id: 'mail.driver.ok',
                checkId: $this->id(),
                title: 'Mail driver aceptable',
                description: 'Driver de correo: '.$driver,
                category: $this->category(),
                meta: ['driver' => $driver],
            ),
        ];
    }
}
