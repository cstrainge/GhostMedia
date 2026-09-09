# 01. Architecture and requirements

## 1. Product contract

The user selects **GhostMedia Speakers** as a Windows playback device. Applications
render through the normal Windows audio stack. In Windows Control Panel, the user
selects one configured Apple output server (a macOS or iOS GhostMedia app). The
Windows user-mode service takes the resulting PCM audio and streams it to that
server, which plays it through the Apple system's currently configured default output.

The Control Panel discovers candidate Apple servers and supports local pairing and
selection. It persists the selected server's stable ID and approved SPKI; its shown
network name is a routing label only. The Windows driver/service never accepts an
inbound GhostMedia control connection in v1.

The protocol neither enumerates nor selects Apple-attached output devices. A local
system-output change is handled entirely by the Apple output server and never changes
the configured GhostMedia server identity.

The Windows endpoint MUST remain usable without a running service, a configured
peer, a TCP connection, a UDP path, or an available Apple output device. Loss of any
of those components changes remote availability, not Windows device presence.
This guarantee covers designed software behavior. It is not a claim that kernel
bugs, hardware faults, operating-system failure, or driver removal cannot occur.

## 2. Components and ownership

```text
Windows application
    -> Windows audio engine
    -> WinDevice virtual render driver
    -> bounded driver-owned PCM bridge
    -> WinDevice user-mode streaming client
       | TLS/TCP: trust, negotiation, lifecycle, feedback, clock samples
       | protected UDP: path probes, paced audio
       v
    Apple Output Server: mDNS/DNS-SD advertisement
       -> decrypt -> reorder/jitter buffer -> resample -> platform audio output

Both userspace endpoints consume the same `GhostMediaRuntime` library for the
currently implemented TCP socket operations, OpenSSL TLS 1.3,
identity/certificate primitives, TLS exporters, and AES-256-GCM. Future UDP
socket operations belong in this runtime rather than in either platform host.
```

| Component | Owns | Must not depend on |
| --- | --- | --- |
| Driver | Endpoint, render clock, bounded bridge, local counters | Sockets, TLS, codecs, UI, remote consumption |
| Shared runtime | Cross-platform transport sockets, OpenSSL TLS/identity/exporters, AES-GCM, bounded transport I/O | UI, platform audio, driver callbacks, trust decisions |
| Windows control client / media sender | Configured-server selection, runtime session orchestration, source timeline, UDP send keys, packetizer | Apple availability for driver progress |
| Apple output server / media receiver | Discovery, protected identity/trust persistence, runtime listener orchestration, playout clock and jitter buffer | Arrival of one packet per output callback |
| Windows Control Panel | Server selection, trust decisions, configuration, status | Participation in real-time processing |

`shared/` contains the deterministic protocol core. `runtime/` contains the
cross-platform networking and OpenSSL implementation used by both userspace
endpoints. `WinDevice/` contains Windows-only driver, service, and supporting
UI/build code. `AppleOutputServer/` contains the macOS application; an iOS implementation follows
the same Apple output-server role while its app is active. When an iOS app cannot
continue its listener or audio output under the operating system's lifecycle rules,
it withdraws discovery and stops the active stream; Windows reconnects only after the
app is available again. The protocol specification
and cross-platform wire fixtures live under `docs/`; neither implementation is
the authority for correcting a disagreement with this specification.

In v1, **Windows control client** means the TCP-initiating Windows service and
**Windows media sender** means that same service while sending Windows-to-Apple
AUDIO. **Apple output server** means the TCP-listening macOS/iOS app and **Apple
media receiver** means that app while receiving and playing AUDIO. Sender and receiver
always describe a media direction, never an inferred TCP role.

## 3. Required invariants

1. Driver progress never waits for a user-mode read or remote acknowledgment.
2. Every queue has a fixed capacity and a documented overflow action.
3. Old audio is discarded when it cannot meet its playout deadline.
4. Device, peer, session, stream, and packet identities have distinct lifetimes.
5. Discovery text cannot authorize access or redirect an established media path.
6. TCP controls state; UDP cannot create streams or change negotiated formats.
7. Lost UDP packets do not trigger audio retransmission or TCP fallback.
8. No packet is decrypted under keys from a different session.
9. A connection failure cannot silently reconnect to an untrusted identity.
10. Audio callbacks and driver scheduling continue using silence/discard policies
    when downstream work fails.

## 4. Baseline and exclusions

Version 1 supports one Windows render endpoint, one selected Apple output server,
and one active Windows-to-Apple audio stream. Up to four authenticated TCP sessions
may inspect state; only one can own the audio subscription. Opening the stream
acquires that ownership. A competing open returns `RESOURCE_BUSY`; it never ejects
the owner.

The baseline is 48,000 sample frames/second, channels `[FL, FR]`, PCM signed 16-bit
little-endian, 240 frames/datagram. One sample frame contains one sample from
each channel. A packet therefore contains 960 bytes of PCM. Windows endpoint
format and negotiated network format are separate contracts; conversion belongs
in the service, not in network negotiation with the driver.

V1 does not define Internet traversal, multicast audio, broadcast media, multiroom
synchronization, exclusive remote device control, file transfer, screen capture,
remote command execution, microphone capture, or camera capture. Addresses entered
manually may work over routed networks, but all v1 transport limits still apply.

## 5. Identities and time domains

| Name | Encoding | Scope and assignment |
| --- | --- | --- |
| `peer_id` | 52 lowercase unpadded base32 characters | SHA-256 of identity public key's DER SubjectPublicKeyInfo; persists with key and is never advertised |
| `server_id` | Lowercase UUID with hyphens | CSPRNG installation identity for one Apple GhostMedia output server; persists across hostname, mDNS-label, address, and certificate renewal changes |
| `endpoint_id` | Lowercase UUID with hyphens | Windows endpoint identity, persists across service restart |
| `boot_id` | Lowercase UUID with hyphens | Apple output-server CSPRNG; new for each Apple output-server process instance |
| `session_id` | 32 lowercase hex characters / 16 raw bytes | Apple output-server CSPRNG; new for each accepted control session |
| `stream_id` | JSON unsigned 32-bit integer / network u32 | Apple output server allocates monotonically from 1 within session when reserving a stream; never reused |
| `key_epoch` | Unsigned 32-bit integer | Starts at 1 per stream direction; changes through the authenticated rekey transition |
| `request id` | JSON unsigned 32-bit integer | Monotonic per request sender, beginning at 1 per TCP connection |
| `sequence` | Unsigned 64-bit integer in UDP | Random start per stream direction and key epoch; never reused under its key |
| `media_timestamp` | Unsigned 64-bit sample-frame count | Windows media sender's source-frame timeline after conversion to the negotiated network sample rate; never wall-clock time |
| `monotonic_ns` | Decimal string | Nanoseconds in the sending process's monotonic clock domain |

Names shown to users are mutable labels, never keys. Identical names do not imply
identical devices. UUIDs are generated using a cryptographically secure random
source with UUID version/variant bits. The peer identifier is an authenticated
pairing-only value; hexadecimal IDs have no prefix or separators unless UUID syntax
is explicitly required.

`server_id` is the Windows client's stable configured-server selector, not an
authorization credential or network address. Windows stores it alongside the locally
approved Apple-server peer identity. On the first successful authorized session after
local pairing, Windows atomically binds the authenticated hello's `server_id` to that
approved SPKI. On every later connection, discovery finds candidate routes and
Windows accepts a candidate only when both TLS pin validation succeeds and its authenticated
`server_id` equals the configured value. A changed computer name, DNS-SD instance
label, address, port, or renewed same-key certificate therefore cannot make Windows
select a different configured server. Loss or intentional reset of the persisted
server ID is a replacement-server event and requires local reconfiguration.

Windows alone chooses initial source timestamps, advances them for every source frame
including timestamped silence, and declares source discontinuities. The Apple media
receiver may validate alignment, retain rendered timestamps, and flush/reprime on a
declared or detected discontinuity, but MUST NOT invent or renumber the Windows source
timeline.

Monotonic clock origins differ across machines and process restarts. Suspend/resume
invalidates timing estimates and forces a fresh session. Drivers use the operating
system's appropriate monotonic/performance counter independently of the session.

## 6. Authority and transactions

The Windows control client/media sender is authoritative for the Windows endpoint,
source audio, source media timestamps, and sender-side path validation. The Apple
output server/media receiver is authoritative for its current subscriber, stream
allocation, negotiated state, local output availability, jitter/playout state, and
actual rendered-timestamp statistics. Neither may fabricate the other's observations.
Status distinguishes `control_connected`, `path_validated`,
`stream_active`, and `audio_audible`; active packets do not prove audible output.

Windows initiates all lifecycle operations. Either side can ping or close a session.
Either side may stop a stream on failure and announces this in an event. A request
response describes a committed state transition; sending a request is not evidence
that it committed. If the connection fails before a response, Windows considers
the result unknown and discards the session. It does not replay the mutation on
a new session as though it were the same transaction.

## 7. Working performance targets

These are targets to measure, not guarantees inferred from transport choice:

- Nominal receiver buffer: 30 ms; negotiated admissible target: 15-120 ms.
- PCM packet interval: 5 ms. Optional Opus interval: 10 ms.
- Driver bridge capacity/freshness: 100/50 ms; service send capacity/freshness:
  40/20 ms. Both discard oldest complete blocks above the freshness threshold.
- Healthy LAN target: less than 100 ms end-to-end at the 95th percentile, measured
  from Windows render presentation to analog/digital output on the Apple device.
- Remote disappearance: driver continues indefinitely; network session is cleaned
  up within the heartbeat timeout when no valid control messages arrive.

Scheduling, Windows mix periods, codec delay, Apple hardware buffers, and wireless
jitter all contribute. The specification requires reporting measurable components
instead of presenting a single unverified latency value.
