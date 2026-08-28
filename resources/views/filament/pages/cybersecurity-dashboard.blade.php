<x-filament-panels::page>
    <div class="space-y-6">
        <div class="rounded-xl border border-gray-200 bg-white p-4 text-sm text-gray-600 shadow-sm dark:border-white/10 dark:bg-gray-900 dark:text-gray-300">
            <div class="flex flex-wrap items-center gap-3">
                <x-filament::badge :color="$this->getGradeColor()">
                    {{ __('filament-cybersecurity::plugin.profile') }}:
                    {{ $this->reportData['profile'] ?? '—' }}
                </x-filament::badge>
                <span>
                    {{ __('filament-cybersecurity::plugin.last_run') }}:
                    {{ $this->reportData['ran_at'] ?? '—' }}
                </span>
            </div>
            <p class="mt-2">
                {{ __('filament-cybersecurity::plugin.brand_hint') }}
            </p>
        </div>

        <div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm dark:border-white/10 dark:bg-gray-900">
            <div class="border-b border-gray-200 px-4 py-3 font-medium dark:border-white/10">
                {{ __('filament-cybersecurity::plugin.findings_heading') }}
            </div>

            <div class="divide-y divide-gray-100 dark:divide-white/5">
                @forelse (($this->reportData['findings'] ?? []) as $finding)
                    <div class="px-4 py-4">
                        <div class="flex flex-wrap items-start justify-between gap-3">
                            <div class="min-w-0 flex-1 space-y-1">
                                <div class="flex flex-wrap items-center gap-2">
                                    <x-filament::badge :color="$finding['status_color']">
                                        {{ $finding['status_label'] }}
                                    </x-filament::badge>
                                    @if ($finding['status'] !== 'passed')
                                        <x-filament::badge :color="$finding['severity_color']">
                                            {{ $finding['severity_label'] }}
                                        </x-filament::badge>
                                    @endif
                                    @if (! empty($finding['category']))
                                        <x-filament::badge color="gray">
                                            {{ __('filament-cybersecurity::plugin.category.' . $finding['category']) }}
                                        </x-filament::badge>
                                    @endif
                                </div>
                                <h3 class="text-sm font-semibold text-gray-950 dark:text-white">
                                    {{ $finding['title'] }}
                                </h3>
                                <p class="text-sm text-gray-600 dark:text-gray-300">
                                    {{ $finding['description'] }}
                                </p>
                                @if (! empty($finding['remediation']))
                                    <p class="text-sm text-primary-600 dark:text-primary-400">
                                        <span class="font-medium">{{ __('filament-cybersecurity::plugin.remediation') }}:</span>
                                        {{ $finding['remediation'] }}
                                    </p>
                                @endif
                            </div>
                            <code class="shrink-0 text-xs text-gray-400">{{ $finding['id'] }}</code>
                        </div>
                    </div>
                @empty
                    <div class="px-4 py-8 text-center text-sm text-gray-500">
                        {{ __('filament-cybersecurity::plugin.no_findings') }}
                    </div>
                @endforelse
            </div>
        </div>
    </div>
</x-filament-panels::page>
