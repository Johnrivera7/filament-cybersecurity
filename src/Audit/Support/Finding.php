<?php

declare(strict_types=1);

namespace JohnRivera7\FilamentCybersecurity\Audit\Support;

use JohnRivera7\FilamentCybersecurity\Audit\Enums\CheckStatus;
use JohnRivera7\FilamentCybersecurity\Audit\Enums\Severity;

final class Finding
{
    /**
     * @param  array<string, mixed>  $meta  Never put raw secrets here.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $checkId,
        public readonly string $title,
        public readonly string $description,
        public readonly Severity $severity,
        public readonly CheckStatus $status,
        public readonly ?string $remediation = null,
        public readonly array $meta = [],
        public readonly ?string $category = null,
    ) {}

    /**
     * @param  array<string, mixed>  $meta
     */
    public static function fail(
        string $id,
        string $checkId,
        string $title,
        string $description,
        Severity $severity,
        ?string $remediation = null,
        array $meta = [],
        ?string $category = null,
    ): self {
        return new self(
            id: $id,
            checkId: $checkId,
            title: $title,
            description: $description,
            severity: $severity,
            status: CheckStatus::Failed,
            remediation: $remediation,
            meta: $meta,
            category: $category,
        );
    }

    /**
     * @param  array<string, mixed>  $meta
     */
    public static function pass(
        string $id,
        string $checkId,
        string $title,
        string $description,
        ?string $category = null,
        array $meta = [],
    ): self {
        return new self(
            id: $id,
            checkId: $checkId,
            title: $title,
            description: $description,
            severity: Severity::Info,
            status: CheckStatus::Passed,
            remediation: null,
            meta: $meta,
            category: $category,
        );
    }

    /**
     * @param  array<string, mixed>  $meta
     */
    public static function warn(
        string $id,
        string $checkId,
        string $title,
        string $description,
        Severity $severity = Severity::Medium,
        ?string $remediation = null,
        array $meta = [],
        ?string $category = null,
    ): self {
        return new self(
            id: $id,
            checkId: $checkId,
            title: $title,
            description: $description,
            severity: $severity,
            status: CheckStatus::Warning,
            remediation: $remediation,
            meta: $meta,
            category: $category,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'check_id' => $this->checkId,
            'title' => $this->title,
            'description' => $this->description,
            'severity' => $this->severity->value,
            'severity_label' => $this->severity->label(),
            'severity_color' => $this->severity->color(),
            'status' => $this->status->value,
            'status_label' => $this->status->label(),
            'status_color' => $this->status->color(),
            'remediation' => $this->remediation,
            'meta' => $this->meta,
            'category' => $this->category,
        ];
    }
}
