<script lang="ts">
    import { req, get_config, GpsMode } from '$lib/utils.svelte';

    type Status = 'idle' | 'watching' | 'error';

    let status: Status = $state('idle');
    let watch_id: number | null = null;

    let last_fix: { latitude: number; longitude: number; accuracy: number } | null = $state(null);
    let last_fix_at: Date | null = $state(null);
    let last_post_at: Date | null = $state(null);
    let last_post_error: string | null = $state(null);
    let geolocation_error: string | null = $state(null);

    let gps_mode: GpsMode | null = $state(null);
    let gps_mode_error: string | null = $state(null);
    let show_cert_trust_help: boolean = $state(false);

    const is_secure_context = typeof window !== 'undefined' && window.isSecureContext;
    const has_geolocation = typeof navigator !== 'undefined' && !!navigator.geolocation;

    $effect(() => {
        get_config()
            .then((config) => {
                gps_mode = config.gps_mode;
            })
            .catch((e) => {
                gps_mode_error = `Couldn't load device configuration: ${e}`;
            });
    });

    function format_time(d: Date | null): string {
        return d ? d.toLocaleTimeString() : 'never';
    }

    function on_position(position: GeolocationPosition) {
        geolocation_error = null;
        last_fix = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
        };
        last_fix_at = new Date();

        req('POST', '/api/gps', {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
        })
            .then(() => {
                last_post_at = new Date();
                last_post_error = null;
            })
            .catch((e) => {
                last_post_error = `${e}`;
            });
    }

    function on_error(error: GeolocationPositionError) {
        status = 'error';
        switch (error.code) {
            case error.PERMISSION_DENIED:
                geolocation_error =
                    'Location permission was denied. Check your browser/device location settings and try again.';
                show_cert_trust_help = true;
                break;
            case error.POSITION_UNAVAILABLE:
                geolocation_error = 'Location is currently unavailable.';
                break;
            case error.TIMEOUT:
                geolocation_error = 'Timed out waiting for a location fix.';
                break;
            default:
                geolocation_error = error.message || 'Unknown geolocation error.';
        }
    }

    function start_sharing() {
        geolocation_error = null;
        watch_id = navigator.geolocation.watchPosition(on_position, on_error, {
            enableHighAccuracy: true,
            maximumAge: 5000,
            timeout: 15000,
        });
        status = 'watching';
    }

    function stop_sharing() {
        if (watch_id !== null) {
            navigator.geolocation.clearWatch(watch_id);
            watch_id = null;
        }
        status = 'idle';
    }
</script>

<svelte:head>
    <title>Rayhunter GPS</title>
</svelte:head>

<div class="min-h-screen bg-gray-50 flex flex-col items-center px-4 py-8">
    <div class="w-full max-w-md space-y-4">
        <div class="p-4 bg-rayhunter-blue drop-shadow-sm rounded-lg text-white">
            <h1 class="text-xl font-bold">Rayhunter GPS</h1>
            <p class="text-sm opacity-90">
                Share this phone's location with your Rayhunter device while it's connected to its
                WiFi.
            </p>
        </div>

        {#if !is_secure_context}
            <div class="p-4 bg-red-100 border border-red-400 text-red-800 rounded-lg text-sm">
                <p class="font-semibold">This page isn't loaded over HTTPS.</p>
                <p class="mt-1">
                    Browsers only allow location access on a secure page. Load this page using
                    <code>https://</code> instead (port 8443 by default), e.g.
                    <code
                        >https://{typeof window !== 'undefined'
                            ? window.location.hostname
                            : '<device-ip>'}:8443/gps</code
                    >. You'll need to accept the "not trusted" certificate warning once.
                </p>
            </div>
        {:else if !has_geolocation}
            <div class="p-4 bg-red-100 border border-red-400 text-red-800 rounded-lg text-sm">
                This browser doesn't support the Geolocation API.
            </div>
        {:else}
            {#if gps_mode !== null && gps_mode !== GpsMode.Api}
                <div
                    class="p-4 bg-yellow-100 border border-yellow-400 text-yellow-800 rounded-lg text-sm"
                >
                    GPS mode is not set to <strong>API Endpoint</strong> in the device's configuration,
                    so location updates sent from here won't be recorded. Change it in the main Rayhunter
                    UI's GPS Settings.
                </div>
            {/if}
            {#if gps_mode_error}
                <div
                    class="p-4 bg-yellow-100 border border-yellow-400 text-yellow-800 rounded-lg text-sm"
                >
                    {gps_mode_error}
                </div>
            {/if}

            <div class="p-4 bg-white border border-gray-200 rounded-lg shadow-sm space-y-3">
                {#if status !== 'watching'}
                    <button
                        onclick={start_sharing}
                        class="w-full px-4 py-2 bg-rayhunter-blue text-white rounded-md font-medium hover:opacity-90"
                    >
                        Start sharing location
                    </button>
                {:else}
                    <button
                        onclick={stop_sharing}
                        class="w-full px-4 py-2 bg-gray-200 text-gray-800 rounded-md font-medium hover:bg-gray-300"
                    >
                        Stop sharing location
                    </button>
                {/if}

                {#if geolocation_error}
                    <p class="text-sm text-red-700">{geolocation_error}</p>
                {/if}

                {#if show_cert_trust_help}
                    <div
                        class="p-3 bg-yellow-50 border border-yellow-300 text-yellow-900 rounded-md text-sm space-y-2"
                    >
                        <p class="font-semibold">Still denied after allowing location access?</p>
                        <p>
                            Clicking through the "not trusted" warning only lets this page load — it
                            isn't enough for iOS/Safari to grant location access. You need to
                            install and fully trust this device's certificate once:
                        </p>
                        <ol class="list-decimal list-inside space-y-1">
                            <li>
                                <a href="/cert.pem" class="underline font-medium"
                                    >Tap here to download the certificate</a
                                >, then tap "Allow" if prompted.
                            </li>
                            <li>
                                Go to <strong
                                    >Settings → General → VPN &amp; Device Management</strong
                                >, tap the downloaded profile, then <strong>Install</strong> (twice, confirming
                                any warnings).
                            </li>
                            <li>
                                Go to <strong
                                    >Settings → General → About → Certificate Trust Settings</strong
                                >
                                and turn on full trust for <strong>Rayhunter</strong>.
                            </li>
                            <li>Come back to this page and tap "Start sharing location" again.</li>
                        </ol>
                    </div>
                {/if}

                {#if last_fix}
                    <dl class="text-sm text-gray-700 grid grid-cols-2 gap-x-2 gap-y-1">
                        <dt class="text-gray-500">Latitude</dt>
                        <dd>{last_fix.latitude.toFixed(6)}</dd>
                        <dt class="text-gray-500">Longitude</dt>
                        <dd>{last_fix.longitude.toFixed(6)}</dd>
                        <dt class="text-gray-500">Accuracy</dt>
                        <dd>±{Math.round(last_fix.accuracy)} m</dd>
                        <dt class="text-gray-500">Last fix</dt>
                        <dd>{format_time(last_fix_at)}</dd>
                        <dt class="text-gray-500">Last sent to device</dt>
                        <dd>{format_time(last_post_at)}</dd>
                    </dl>
                {/if}

                {#if last_post_error}
                    <p class="text-sm text-red-700">
                        Couldn't send location to the device: {last_post_error}
                    </p>
                {/if}
            </div>

            <p class="text-xs text-gray-500">
                Keep this tab open and your phone connected to the Rayhunter's WiFi while recording.
                Location is only sent to this device on its local network, nowhere else.
            </p>
        {/if}
    </div>
</div>
