# 07. Lifecycle, recovery, and limits

## State machines

Apple output-server session states are `LISTENING -> TLS -> HELLO -> BOUND ->
STREAM_OPEN -> STREAMING -> STREAM_OPEN`, with `CLOSED` reachable from every state.
`STREAM_OPEN` means reserved but silent. Windows control-client states follow the
same session progression after it initiates TCP; sender-side `PATH_PROBING` is local
between `STREAM_OPEN` and `STREAMING`. Any TLS/control failure goes directly to
`CLOSED`: stop streams, release subscriber ownership, erase keys, and retain driver
operation.

The Apple output-server media receiver states are `IDLE -> PRIMING -> PLAYING -> REPRIMING`, then
back to `IDLE` on stop/close. A successful `stream.start` triggers `PRIMING`; it
does not mean samples are audible. A valid packet never moves state from `IDLE`
without control authorization. `PLAYING` can render concealment/silence on loss.

```text
Win: discover configured server -> TCP/TLS -> hello -> bind -> open -> PATH_CHALLENGE -> PATH_RESPONSE -> start
Apple: advertise -> accept TLS -> hello -> bind -> open -> receive challenge -> response -> start
                       \-----------------------------------------------/
                              control owns all transitions
UDP:             cannot create/change stream; only probes, audio, feedback
```

## Reconnection and restart

Windows may reconnect after terminal failure with exponential backoff: random delay
uniformly chosen in `[0, 250]` ms for first retry, then a multiplier of 1.5 to 2.0,
capped at 10 seconds. Reset backoff only after a session has streamed for 30 seconds.
It must resolve the current mDNS/manual address again, perform TLS pin validation,
and create a fresh session. It MUST NOT reuse session IDs, UDP keys, packet indices,
stream IDs, source packets, outstanding probes, or an unknown old request outcome.

Windows service restart generates a new bridge epoch and client session material; it
opens any replacement stream with a newly declared Windows source-timestamp boundary.
The Apple output server generates a new `boot_id` on restart and may keep its
long-term identity and mDNS instance. Windows detects a changed Apple `boot_id` only
after new authenticated hello; the Apple media receiver flushes all old media after a
new `stream.start` boundary. Driver restart/format loss stops existing streams with a
state event where possible. Apple
system-default output route/rate changes flush/reprime locally and keep control only
if its output continues; otherwise feedback indicates loss and Windows stops after
timeout. Such a local route change never changes `server_id` or requires Windows
reconfiguration.

The Apple output server subscribes to local interface, address, route, and firewall-profile
changes. Each advertised TCP listener and UDP tuple is bound to a concrete interface
and address family. On loss of that interface, address, route, or permission to use
it, the server immediately withdraws its affected DNS-SD record, stops accepting on
the affected listener, invalidates affected UDP path validation, and stops each
affected stream with `NETWORK_INTERFACE_LOST`. It erases its media keys when the
corresponding session closes. It MUST NOT silently migrate an authenticated session
to a newly selected interface or source address: Windows discovers/resolves again,
performs a fresh TLS session and UDP path validation, then opens a new stream. An
address change on a still-present interface follows the same rule unless a new,
authenticated `transport.bind` is completed within the existing TLS session and
both peers explicitly support `path_rebind`; v1 does not negotiate `path_rebind`.

On a firewall profile becoming public, an Apple output server using the default private-network
policy withdraws all public-interface advertisements and terminates streams on those
interfaces. It keeps unaffected private-interface sessions only if their exact bound
interface and address remain valid. Interface changes are coalesced for 250 ms for
advertisement updates, but media path invalidation and stream stop are immediate.

When the session-expiry threshold approaches, the Apple output server sends
`event.session.expiring` at least 30 seconds before deadline. Windows stops/closes
then reconnects. If no fresh session exists by deadline, the Apple output server
stops the stream and closes the session. Key
limits always override attempts to avoid an interruption.

## Central limits

| Item | Limit/action |
| --- | --- |
| TLS handshake | 5 seconds |
| hello deadline | 2 seconds after TLS |
| control frame | 2..65,536 UTF-8 bytes |
| queued parsed control frames | 16 |
| pending requests | 4; mutating requests serial |
| active stream subscribers | 1 per Apple output server |
| active TCP sessions | 4 authenticated sessions |
| driver bridge capacity / freshness threshold | 100 ms / 50 ms; discard oldest complete data above freshness threshold |
| service send capacity / freshness threshold | 40 ms / 20 ms; discard oldest complete data above freshness threshold |
| receiver target buffer | 15..120 ms; default 30 ms |
| receiver jitter capacity | 300 ms, `ceil(300 ms / packet_interval)` packets, and 64 KiB per stream |
| accepted media lookbehind/lookahead | 120/250 ms |
| UDP datagram | 80..1,500 bytes |
| GCM epoch / sequence lifetime | rekey before 30 minutes, 2^32 packets, or sequence exhaustion |
| control session lifetime | at most 12 hours; announce expiry at least 30 seconds before close |
| replay window | 1,024 sequences per stream direction and key epoch |
| path challenge | at most 3, one/second; 5-second deadline; refresh before 30-second expiry |
| feedback interval / failure | 500 ms / 3 seconds |
| ping interval / control timeout | 2 seconds / 6 seconds |
| initial prime wait | 500 ms |

All limits are inclusive where a range is shown. On a violation, reject only the
offending frame/packet when parser synchronization and authentication remain sound;
close the control connection for invalid framing, repeated authenticated abuse, or
state ambiguity. Limits are independently configurable only if doing so cannot
break wire interoperability or bounded-resource guarantees.

## Observability

Use structured local events with timestamp, peer ID, session ID, stream ID, state,
and error code when applicable. Never log plaintext audio, traffic keys, exporter
material, full certificates, or identity cards. Hash/omit raw remote IP in privacy
mode. Expose counters: control parse/auth failures, UDP drops by reason, replay
drops, packet loss/late/concealment, buffer occupancy/underflow/overflow, service
queue drops, bridge drops, active resampler ppm, reconnect count, and state duration.

Status is eventually sampled and must identify its snapshot time. Rate-limit noisy
events. Metrics remain local by default; no telemetry upload is specified.
