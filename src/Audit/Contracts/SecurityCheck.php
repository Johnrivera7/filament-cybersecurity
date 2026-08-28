<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Contracts;

use JohnRivera7\FilamentCybersecurity\Audit\Enums\EnvironmentProfile;
use JohnRivera7\FilamentCybersecurity\Audit\Support\Finding;

interface SecurityCheck
{
    public function id(): string;

    public function label(): string;

    public function category(): string;

    public function appliesTo(EnvironmentProfile $profile): bool;

    /**
     * @return list<Finding>
     */
    public function run(EnvironmentProfile $profile): array;
}
