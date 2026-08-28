<details class="fcs-meta">
    <summary>{{ __('filament-cybersecurity::plugin.view_details') }}</summary>
    <div class="fcs-meta-body">
        @if (isset($meta['samples']) && is_array($meta['samples']))
            <table class="fcs-meta-table">
                <thead>
                    <tr>
                        <th>{{ __('filament-cybersecurity::plugin.meta_uri') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_methods') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_name') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($meta['samples'] as $sample)
                        <tr>
                            <td><code>/{{ $sample['uri'] ?? '—' }}</code></td>
                            <td>{{ implode(', ', $sample['methods'] ?? []) }}</td>
                            <td>{{ $sample['name'] ?? '—' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        @elseif (isset($meta['advisories']) && is_array($meta['advisories']))
            <table class="fcs-meta-table">
                <thead>
                    <tr>
                        <th>{{ __('filament-cybersecurity::plugin.meta_package') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_severity') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_cve') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_title') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($meta['advisories'] as $advisory)
                        <tr>
                            <td><code>{{ $advisory['package'] ?? '—' }}</code></td>
                            <td>{{ $advisory['severity'] ?? '—' }}</td>
                            <td>
                                @if (! empty($advisory['link']))
                                    <a href="{{ $advisory['link'] }}" target="_blank" rel="noopener noreferrer">{{ $advisory['cve'] ?? $advisory['title'] ?? '—' }}</a>
                                @else
                                    {{ $advisory['cve'] ?? '—' }}
                                @endif
                            </td>
                            <td>{{ $advisory['title'] ?? '—' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        @elseif (isset($meta['plugins']) && is_array($meta['plugins']))
            <table class="fcs-meta-table">
                <thead>
                    <tr>
                        <th>{{ __('filament-cybersecurity::plugin.meta_package') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_version') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($meta['plugins'] as $plugin)
                        <tr>
                            <td><code>{{ $plugin['package'] ?? '—' }}</code></td>
                            <td>{{ $plugin['version'] ?? '—' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        @elseif (isset($meta['packages']) && is_array($meta['packages']))
            <table class="fcs-meta-table">
                <thead>
                    <tr>
                        <th>{{ __('filament-cybersecurity::plugin.meta_package') }}</th>
                        <th>{{ __('filament-cybersecurity::plugin.meta_version') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($meta['packages'] as $package)
                        <tr>
                            <td><code>{{ $package['package'] ?? '—' }}</code></td>
                            <td>{{ $package['version'] ?? '—' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        @elseif (isset($meta['missing_in_env']) || isset($meta['extra_in_env']) || isset($meta['missing_critical']))
            <dl class="grid gap-2">
                @if (! empty($meta['missing_critical']))
                    <div>
                        <dt class="font-semibold text-[var(--fcs-muted)]">{{ __('filament-cybersecurity::plugin.meta_missing_critical') }}</dt>
                        <dd><code>{{ implode(', ', $meta['missing_critical']) }}</code></dd>
                    </div>
                @endif
                @if (! empty($meta['missing_in_env']))
                    <div>
                        <dt class="font-semibold text-[var(--fcs-muted)]">{{ __('filament-cybersecurity::plugin.meta_missing_in_env') }}</dt>
                        <dd><code>{{ implode(', ', $meta['missing_in_env']) }}</code></dd>
                    </div>
                @endif
                @if (! empty($meta['extra_in_env']))
                    <div>
                        <dt class="font-semibold text-[var(--fcs-muted)]">{{ __('filament-cybersecurity::plugin.meta_extra_in_env') }}</dt>
                        <dd><code>{{ implode(', ', $meta['extra_in_env']) }}</code></dd>
                    </div>
                @endif
            </dl>
        @else
            <dl class="grid gap-1 sm:grid-cols-2">
                @foreach ($meta as $key => $value)
                    <div>
                        <dt class="font-semibold text-[var(--fcs-muted)]">{{ $key }}</dt>
                        <dd>
                            @if (is_array($value))
                                <code>{{ json_encode($value, JSON_UNESCAPED_UNICODE) }}</code>
                            @elseif (is_bool($value))
                                {{ $value ? 'true' : 'false' }}
                            @else
                                {{ $value }}
                            @endif
                        </dd>
                    </div>
                @endforeach
            </dl>
        @endif
    </div>
</details>
