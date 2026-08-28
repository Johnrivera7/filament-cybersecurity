@php
    $counts = $this->getCounts();
    $summary = $this->getSummary();
    $score = $this->getScore();
    $grade = $this->getGrade();
@endphp

<x-filament-panels::page>
    <div class="fcs-dashboard">
        {{-- Hero: score donut + stats --}}
        <section class="fcs-hero">
            <div class="fcs-badges">
                <span class="fcs-badge">
                    <span class="fcs-badge-dot"></span>
                    {{ __('filament-cybersecurity::plugin.security_audit') }}
                </span>
                <span class="fcs-badge fcs-badge--live">
                    <span class="fcs-badge-dot fcs-badge-dot--live"></span>
                    {{ __('filament-cybersecurity::plugin.live_scan') }}
                </span>
                <span class="fcs-badge">
                    {{ __('filament-cybersecurity::plugin.profile') }}: {{ $this->reportData['profile'] ?? '—' }}
                </span>
            </div>

            <div class="fcs-hero-top">
                <div>
                    <div class="fcs-hero-title">
                        <x-filament::icon icon="heroicon-o-shield-check" class="h-6 w-6 text-danger-500" />
                        {{ __('filament-cybersecurity::plugin.posture_title') }}
                    </div>
                    <p class="fcs-hero-sub">
                        {{ __('filament-cybersecurity::plugin.posture_sub', [
                            'checks' => $counts['checks'] ?? $counts['total'] ?? 0,
                            'ran' => $this->formattedRanAt(),
                        ]) }}
                    </p>
                </div>

                <div class="fcs-score-block">
                    <div class="fcs-donut" style="--fcs-score: {{ $score }};">
                        <span>{{ $score }}</span>
                    </div>
                    <div>
                        <div class="fcs-grade">{{ __('filament-cybersecurity::plugin.grade_label', ['grade' => $grade]) }}</div>
                        <div class="fcs-grade-label">{{ __('filament-cybersecurity::plugin.score_of_100') }}</div>
                    </div>
                </div>
            </div>

            @if ($this->hasImmediateAction())
                <div class="fcs-alert-banner">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                    <div>
                        <div class="fcs-alert-banner-title">{{ __('filament-cybersecurity::plugin.immediate_action') }}</div>
                        <div class="fcs-alert-banner-text">
                            {{ __('filament-cybersecurity::plugin.immediate_action_detail', [
                                'critical' => $counts['critical'] ?? 0,
                                'high' => $counts['high'] ?? 0,
                            ]) }}
                        </div>
                    </div>
                </div>
            @endif

            <div class="fcs-stats">
                <div class="fcs-stat fcs-stat--critical">
                    <div class="fcs-stat-k">{{ __('filament-cybersecurity::plugin.stat_critical') }}</div>
                    <div class="fcs-stat-v">{{ $counts['critical'] ?? 0 }}</div>
                </div>
                <div class="fcs-stat fcs-stat--high">
                    <div class="fcs-stat-k">{{ __('filament-cybersecurity::plugin.stat_high') }}</div>
                    <div class="fcs-stat-v">{{ $counts['high'] ?? 0 }}</div>
                </div>
                <div class="fcs-stat fcs-stat--medium">
                    <div class="fcs-stat-k">{{ __('filament-cybersecurity::plugin.severity.medium') }}</div>
                    <div class="fcs-stat-v">{{ $counts['medium'] ?? 0 }}</div>
                </div>
                <div class="fcs-stat fcs-stat--passed">
                    <div class="fcs-stat-k">{{ __('filament-cybersecurity::plugin.stat_passed') }}</div>
                    <div class="fcs-stat-v">{{ $counts['passed'] ?? 0 }}</div>
                </div>
            </div>

            @if ($summary !== [])
                <div class="fcs-runtime">
                    @foreach ([
                        'php' => 'PHP',
                        'laravel' => 'Laravel',
                        'filament' => 'Filament',
                        'app_env' => 'APP_ENV',
                        'cache_driver' => 'Cache',
                        'session_driver' => 'Session',
                        'queue_driver' => 'Queue',
                    ] as $key => $label)
                        @if (! empty($summary[$key]))
                            <div class="fcs-runtime-item">
                                <kbd>{{ $label }}</kbd>
                                <span>{{ is_bool($summary[$key]) ? ($summary[$key] ? 'true' : 'false') : $summary[$key] }}</span>
                            </div>
                        @endif
                    @endforeach
                </div>
            @endif
        </section>

        {{-- Findings --}}
        <section class="fcs-card">
            <div class="fcs-card-bar"></div>
            <div class="fcs-card-head">
                <div class="fcs-card-title">{{ __('filament-cybersecurity::plugin.findings_heading') }}</div>
                <div class="fcs-filters">
                    <button type="button" wire:click="$set('filter', 'all')"
                        @class(['fcs-filter-btn', 'is-active' => $filter === 'all'])>
                        {{ __('filament-cybersecurity::plugin.filter_all') }} ({{ $counts['total'] ?? 0 }})
                    </button>
                    <button type="button" wire:click="$set('filter', 'issues')"
                        @class(['fcs-filter-btn', 'is-active' => $filter === 'issues'])>
                        {{ __('filament-cybersecurity::plugin.filter_issues') }} ({{ $counts['failed'] ?? 0 }})
                    </button>
                    <button type="button" wire:click="$set('filter', 'passed')"
                        @class(['fcs-filter-btn', 'is-active' => $filter === 'passed'])>
                        {{ __('filament-cybersecurity::plugin.filter_passed') }} ({{ $counts['passed'] ?? 0 }})
                    </button>
                </div>
            </div>

            <div class="fcs-findings">
                @forelse ($this->getFilteredFindings() as $finding)
                    <article class="fcs-finding" wire:key="finding-{{ $finding['id'] }}">
                        <div class="fcs-finding-row">
                            <div @class(['fcs-finding-icon', $this->findingIconClass($finding['status'])])>
                                @if ($finding['status'] === 'failed')
                                    <svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                                @elseif ($finding['status'] === 'warning')
                                    <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
                                @else
                                    <svg viewBox="0 0 24 24"><path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
                                @endif
                            </div>

                            <span @class(['fcs-tag', $this->tagClass($finding['status'])])>
                                {{ $finding['status_label'] }}
                            </span>

                            <div>
                                <div class="flex flex-wrap items-center gap-2">
                                    <h3 class="fcs-finding-title">{{ $finding['title'] }}</h3>
                                    @if (! empty($finding['category']))
                                        <span class="fcs-tag fcs-tag--warn" style="background: var(--fcs-panel-2); color: var(--fcs-muted); border: 1px solid var(--fcs-border);">
                                            {{ __('filament-cybersecurity::plugin.category.' . $finding['category']) }}
                                        </span>
                                    @endif
                                </div>
                                <p class="fcs-finding-desc">{{ $finding['description'] }}</p>
                                <p class="fcs-finding-check">{{ $finding['check_id'] }} · {{ $finding['id'] }}</p>

                                @if (! empty($finding['remediation']))
                                    <div class="fcs-finding-remediation">
                                        <strong>{{ __('filament-cybersecurity::plugin.remediation') }}:</strong>
                                        {{ $finding['remediation'] }}
                                    </div>
                                @endif

                                @if (! empty($finding['meta']))
                                    @include('filament-cybersecurity::filament.partials.finding-meta', ['meta' => $finding['meta']])
                                @endif
                            </div>

                            <span @class(['fcs-sev', $this->sevClass($finding['severity'], $finding['status'])])>
                                {{ $finding['status'] === 'passed' ? 'OK' : strtoupper($finding['severity']) }}
                            </span>
                        </div>
                    </article>
                @empty
                    <div class="fcs-empty">{{ __('filament-cybersecurity::plugin.no_findings') }}</div>
                @endforelse
            </div>
        </section>

        <p class="text-xs text-gray-500 dark:text-gray-400">
            {{ __('filament-cybersecurity::plugin.brand_hint') }}
        </p>
    </div>
</x-filament-panels::page>
