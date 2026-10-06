<script lang="ts">
    import type { CellStatus, MatchedTowerStatus } from '$lib/utils.svelte';

    let {
        status = null,
        enabled = false,
    }: {
        status?: CellStatus | null;
        enabled?: boolean;
    } = $props();

    function format_distance(meters: number): string {
        return meters >= 1000 ? `${(meters / 1000).toFixed(1)} km` : `${Math.round(meters)} m`;
    }

    function format_location(tower: MatchedTowerStatus): string {
        return `${tower.lat.toFixed(4)}, ${tower.lon.toFixed(4)}`;
    }

    // Mirrors GPS_MISMATCH_MIN_METERS / GPS_MISMATCH_RANGE_MULTIPLIER in
    // lib/src/analysis/cell_tower_anomaly.rs -- this is just a visual hint,
    // the actual warning already fired server-side.
    function is_mismatch(tower: MatchedTowerStatus): boolean {
        return tower.distance_m !== null && tower.distance_m > Math.max(tower.range_m * 3, 5000);
    }

    function format_time(iso: string): string {
        return new Date(iso).toLocaleTimeString();
    }
</script>

{#if enabled}
    <div
        class="flex-1 drop-shadow-sm p-4 flex flex-col gap-2 border rounded-md bg-gray-100 border-gray-100"
    >
        <p class="text-xl mb-2">Serving Cell</p>
        {#if !status || (status.pci === null && status.eci === null)}
            <p class="text-sm text-gray-400">Waiting for signal measurements...</p>
        {:else}
            <table class="text-sm w-full">
                <tbody>
                    {#if status.plmn !== null}
                        <tr class="border-b border-gray-200">
                            <td class="py-1 pr-4 text-gray-500 font-medium">PLMN / TAC / ECI</td>
                            <td class="py-1 font-mono"
                                >{status.plmn} / {status.tac} / {status.eci}</td
                            >
                        </tr>
                    {/if}
                    {#if status.pci !== null}
                        <tr class="border-b border-gray-200">
                            <td class="py-1 pr-4 text-gray-500 font-medium">PCI</td>
                            <td class="py-1 font-mono">{status.pci}</td>
                        </tr>
                    {/if}
                    {#if status.rsrp_dbm !== null}
                        <tr class="border-b border-gray-200">
                            <td class="py-1 pr-4 text-gray-500 font-medium">Signal (RSRP)</td>
                            <td class="py-1 font-mono">{status.rsrp_dbm.toFixed(1)} dBm</td>
                        </tr>
                    {/if}
                    {#if status.neighbor_count !== null}
                        <tr class="border-b border-gray-200">
                            <td class="py-1 pr-4 text-gray-500 font-medium">Neighbor Cells</td>
                            <td class="py-1 font-mono">{status.neighbor_count}</td>
                        </tr>
                    {/if}
                    <tr>
                        <td class="py-1 pr-4 text-gray-500 font-medium align-top"
                            >OpenCellID Match</td
                        >
                        <td class="py-1">
                            {#if status.matched_tower}
                                {@const mismatch = is_mismatch(status.matched_tower)}
                                <span class={mismatch ? 'text-red-700 font-semibold' : ''}>
                                    Registered near {format_location(status.matched_tower)}
                                    {#if status.matched_tower.distance_m !== null}
                                        ({format_distance(status.matched_tower.distance_m)} from current
                                        GPS fix{mismatch ? ' -- mismatch!' : ''})
                                    {/if}
                                </span>
                            {:else if status.cell_unknown_to_opencellid}
                                <span class="text-gray-400">Not in bundled database</span>
                            {:else}
                                <span class="text-gray-400">Awaiting cell identity...</span>
                            {/if}
                        </td>
                    </tr>
                </tbody>
            </table>
        {/if}

        {#if status && status.history.length > 0}
            <p class="text-sm font-medium text-gray-500 mt-3">Tower History (this recording)</p>
            <table class="text-sm w-full">
                <thead>
                    <tr class="border-b border-gray-200 text-gray-500">
                        <th class="py-1 pr-4 text-left font-medium">Time</th>
                        <th class="py-1 pr-4 text-left font-medium">PLMN / TAC / ECI</th>
                        <th class="py-1 text-left font-medium">OpenCellID</th>
                    </tr>
                </thead>
                <tbody>
                    {#each [...status.history].reverse() as sighting (sighting.first_seen)}
                        <tr class="border-b border-gray-100">
                            <td class="py-1 pr-4 font-mono">{format_time(sighting.first_seen)}</td>
                            <td class="py-1 pr-4 font-mono"
                                >{sighting.plmn ?? '?'} / {sighting.tac} / {sighting.eci}</td
                            >
                            <td class="py-1">
                                {#if sighting.matched_tower}
                                    {format_location(sighting.matched_tower)}
                                {:else if sighting.cell_unknown_to_opencellid}
                                    <span class="text-gray-400">Not in database</span>
                                {:else}
                                    <span class="text-gray-400">-</span>
                                {/if}
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        {/if}
    </div>
{/if}
