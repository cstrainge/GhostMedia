# 05. Audio, clocks, and latency

## Audio representation

The Windows service converts the driver's local bridge PCM to the negotiated
network profile. It uses a fixed, testable channel matrix and sample-rate
conversion. Baseline output is stereo: mono duplicates to L/R, and surround uses
a documented downmix. Windows mix negotiation handles endpoint formats; the Apple output server
does not negotiate the driver's native format.

`pcm_s16le` samples are signed, interleaved, little-endian two's-complement values
in `-32768..32767`. Float payload, dither metadata, planar layout, and alternate
endianness are not implicit. Float-to-s16 conversion clamps to `[-1,1]`, scales
nonnegative values by 32767 and negative values by 32768, rounds ties away from
zero, then clamps. Optional dithering is local and cannot change timeline or length.

The baseline packet interval is 5 ms. It is independent from Windows mix period
and Mac device callback size. The service accumulates and slices through a bounded
conversion ring; it never makes a driver callback align to the network cadence.

## Timeline and playout

The Windows source timeline is u64 sample frames at the negotiated sample rate.
`media_timestamp` names the first network frame in a packet after conversion. It
advances by `frames_per_packet` through silence and dropped blocks. It resets only
with new stream/session state, so a stream ID defines its epoch.

The Apple output server tracks source timestamp, its receive monotonic clock, and its output-device
clock. Clocks have no shared origin or guaranteed equal rate. `monotonic_ns` is
diagnostic/liveness data and is never subtracted between machines.

After `stream.start`, the Apple output server primes from the first valid packet until it has the
accepted playout target, then sets expected timestamp to the first packet. A gap
over 120 ms, timestamp regression, or declared discontinuity flushes and reprimes.
Initial prime wait is capped at 500 ms; thereafter it reports output loss instead
of retaining stale data.

## Drift and latency

The Apple output server keeps jitter occupancy near target with a slow adaptive resampler after
decode. It derives correction from mean occupancy error over a 2-second window,
not individual packet arrival. Default correction is 0.5 ppm per millisecond of
error, limited to +/-200 ppm. Another stable controller is allowed but correction
MUST remain within +/-300 ppm and its active rate must be observable.

If occupancy remains beyond target +/-20 ms for three seconds while packets arrive,
flush/reprime and report `CLOCK_OR_NETWORK_UNSTABLE` locally. It does not change
sender rate or timestamps. Feedback is telemetry, not a remote clock command.

### Latency contract and measurement

`under_100_ms` is an observed local-LAN profile, not a guarantee for every Windows
mix period, receiver route, or network. A sender and receiver MUST expose the
following separately measured or estimated components in every status snapshot:

| Component | Baseline local-LAN objective | Measurement meaning |
| --- | --- | --- |
| Windows render-to-bridge | <= 20 ms | Source frame presentation to bridge publication; this includes the Windows endpoint period and is measured at the driver boundary. |
| Bridge residence | <= 50 ms | Publication to service consumption; it is exact from local monotonic markers. |
| Conversion and send residence | <= 20 ms | Service consumption to UDP send; exact local measurement. |
| Network transit | informational | One-way delay is an estimate unless clocks have been explicitly synchronized. |
| Receiver jitter target | 30 ms default, 15..120 ms | First accepted media frame to playout eligibility; measured from source timestamp and receiver clock discipline. |
| Decode/resample and callback handoff | <= 10 ms for PCM | Receiver-local processing to submission to the output callback. Opus reports its algorithmic delay separately. |
| Apple output/device latency | route supplied | Platform-reported device latency plus safety offset; it may exceed the local-LAN objective. |

The product reports the sum only when each locally measurable component is present.
It labels the result `estimated_end_to_end_latency` and includes an `unknown` flag
when a route, clock, or hardware value is unavailable. UDP receipt, packet sequence,
and TCP acknowledgement never prove audible output. The baseline objective is tested
with a 48 kHz PCM stream, a 5 ms packet cadence, a private wired or Wi-Fi LAN, a
Windows endpoint period no greater than 10 ms, and a Mac route whose reported output
latency is no greater than 20 ms. Other routes report their measured budget rather
than claiming this objective.

### Bounded real-time reservoirs

The driver-to-service bridge holds **100 ms** of normalized PCM, divided into fixed
complete blocks. The service starts discarding oldest complete blocks once bridge
residence exceeds **50 ms**; it may retain the remaining 50 ms only to survive a
short ordinary user-mode scheduling stall. The service conversion/send queue holds
at most **40 ms** and discards oldest complete network data above **20 ms** of
residence. These freshness thresholds, rather than buffer capacity, bound normal
added latency.

Each discard advances the applicable source/media timeline, increments a reasoned
counter, and emits one discontinuity when the cumulative discard reaches 120 ms or
when format/epoch changes. A receiver treats that discontinuity as a flush/reprime
boundary. Queue sizing is validated under CPU contention, page faults, endpoint
reconfiguration, logging pressure, and a 50 ms service scheduling pause; those tests
may revise capacities only after the latency budget is revised with them.

Digital silence is zero PCM. Windows mixer volume/mute acts before the bridge;
Apple output volume remains local. The Apple output server follows the system default
output and does not expose remote device enumeration or route selection. A service
discontinuity occurs after bridge reopen,
conversion reset, stream restart, or dropping at least 120 ms; it flushes state and
requires a new start transaction. Apple-output discontinuities include route/rate change,
reprime, start/stop/close, and source-timestamp anomaly.
