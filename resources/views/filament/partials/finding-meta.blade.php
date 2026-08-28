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
