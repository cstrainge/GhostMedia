# 01. Architecture and requirements

## 1. Product contract

The user selects **GhostMedia Speakers** as a Windows playback device. Applications
render through the normal Windows audio stack. A Windows user-mode service takes
the resulting PCM audio and streams it to the selected Mac. The Mac plays it
through a user-selected local output device.

The Windows endpoint MUST remain usable without a running service, a configured
peer, a TCP connection, a UDP path, or an available Mac output device. Loss of any
of those components changes remote availability, not Windows device presence.
This guarantee covers designed software behavior. It is not a claim that kernel
bugs, hardware faults, operating-system failure, or driver removal cannot occur.

## 2. Components and ownership

```text
Windows application
    -> Windows audio engine
    -> WinDevice virtual render driver
    -> bounded driver-owned PCM bridge
    -> WinDevice user-mode streaming service
       | mDNS/DNS-SD advertisement
       | TLS/TCP: trust, negotiation, lifecycle, feedback, clock samples
       | protected UDP: path probes, paced audio
       v
    Mac Client: decrypt -> reorder/jitter buffer -> resample -> Core Audio
```

| Component | Owns | Must not depend on |
| --- | --- | --- |
| Driver | Endpoint, render clock, bounded bridge, local counters | Sockets, TLS, codecs, UI, remote consumption |
| Windows service | Discovery, identity, TCP sessions, UDP keys, packetizer | Mac availability for driver progress |
| Mac client | Selection, control coordination, UDP receive, playout clock | Arrival of one packet per output callback |
| Windows UI | Trust decisions, configuration, status | Participation in real-time processing |

`WinDevice/` will contain Windows-only driver, service, and supporting UI/build
code. `Mac Client/` will contain the macOS application. The protocol specification
and cross-platform wire fixtures live under `docs/`; neither implementation is
the authority for correcting a disagreement with this specification.

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

Version 1 supports one Windows render endpoint, one Mac receiver, and one active
Windows-to-Mac audio stream. Up to four authenticated TCP sessions may inspect
state; only one can own the audio subscription. Opening the stream acquires that
ownership. A competing open returns `RESOURCE_BUSY`; it never ejects the owner.

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
| `endpoint_id` | Lowercase UUID with hyphens | Windows endpoint identity, persists across service restart |
| `boot_id` | Lowercase UUID with hyphens | New random UUID each service process start |
| `session_id` | 32 lowercase hex characters / 16 raw bytes | Windows CSPRNG; new per accepted hello |
| `stream_id` | JSON unsigned 32-bit integer / network u32 | Windows allocates monotonically from 1 within session; never reused |
| `key_epoch` | Unsigned 32-bit integer | Starts at 1 per stream direction; changes through the authenticated rekey transition |
| `request id` | JSON unsigned 32-bit integer | Monotonic per request sender, beginning at 1 per TCP connection |
| `sequence` | Unsigned 64-bit integer in UDP | Random start per stream direction and key epoch; never reused under its key |
| `media_timestamp` | Unsigned 64-bit sample-frame count | Stream source clock; never wall-clock time |
| `monotonic_ns` | Decimal string | Nanoseconds in the sending process's monotonic clock domain |

Names shown to users are mutable labels, never keys. Identical names do not imply
identical devices. UUIDs are generated using a cryptographically secure random
source with UUID version/variant bits. The peer identifier is an authenticated
pairing-only value; hexadecimal IDs have no prefix or separators unless UUID syntax
is explicitly required.

Monotonic clock origins differ across machines and process restarts. Suspend/resume
invalidates timing estimates and forces a fresh session. Drivers use the operating
system's appropriate monotonic/performance counter independently of the session.

## 6. Authority and transactions

The Windows service is authoritative for endpoint availability, current subscriber,
stream allocation, and negotiated state. The Mac is authoritative for its local
output availability and actual playout statistics. Neither may fabricate the
other's observations. Status distinguishes `control_connected`, `path_validated`,
`stream_active`, and `audio_audible`; active packets do not prove audible output.

The Mac initiates all lifecycle operations. Either side can ping or close a session.
Windows may stop a stream on failure and announces this in an event. A request
response describes a committed state transition; sending a request is not evidence
that it committed. If the connection fails before a response, the Mac considers
the result unknown and discards the session. It does not replay the mutation on
a new session as though it were the same transaction.

## 7. Working performance targets

These are targets to measure, not guarantees inferred from transport choice:

- Nominal receiver buffer: 30 ms; negotiated admissible target: 15-120 ms.
- PCM packet interval: 5 ms. Optional Opus interval: 10 ms.
- Driver bridge capacity/freshness: 100/50 ms; service send capacity/freshness:
  40/20 ms. Both discard oldest complete blocks above the freshness threshold.
- Healthy LAN target: less than 100 ms end-to-end at the 95th percentile, measured
  from Windows render presentation to analog/digital output on the Mac.
- Remote disappearance: driver continues indefinitely; network session is cleaned
  up within the heartbeat timeout when no valid control messages arrive.

Scheduling, Windows mix periods, codec delay, Mac hardware buffers, and wireless
jitter all contribute. The specification requires reporting measurable components
instead of presenting a single unverified latency value.
