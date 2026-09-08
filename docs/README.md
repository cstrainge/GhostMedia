# GhostMedia protocol design

Status: **proposed specification, version 1.0-draft.1**. Date: 2026-09-08.
These documents define the intended implementation; they do not claim that a
driver, service, client, or tested network stack already exists.

GhostMedia presents a persistent Windows playback device and delivers its audio
to a Mac over the network. Windows development belongs in `WinDevice/`. The
macOS application belongs in `Mac Client/` and will be built on a Mac later.
Microphone input and webcam input are future extensions, not version 1 features.

## Read in this order

1. [Architecture and requirements](01-architecture.md): ownership, guarantees,
   scope, identifiers, and the normative baseline.
2. [Discovery and trust](02-discovery-and-security.md): mDNS/DNS-SD, addressing,
   identity provisioning, TLS, authorization, and UDP keys.
3. [TCP control protocol](03-control-protocol.md): framing, types, every v1
   operation, capability negotiation, errors, and transaction semantics.
4. [UDP media protocol](04-media-protocol.md): byte layout, authenticated
   encryption, path validation, replay protection, packetization, and MTU.
5. [Audio and timing](05-audio-and-timing.md): formats, clock mapping, jitter,
   loss, drift, pacing, and latency accounting.
6. [Windows driver/service contract](06-windows-driver-boundary.md): local
   interface design, buffer ownership, timekeeping, and failure containment.
7. [Lifecycle and recovery](07-lifecycle-and-recovery.md): state machines,
   reconnect rules, limits, observability, and failure handling.
8. [Future microphone and camera support](08-future-media.md): reserved
   extension boundaries and decisions intentionally deferred.
9. [Conformance and examples](09-conformance.md): end-to-end trace, acceptance
   tests, byte examples, and cross-platform verification requirements.
10. [Cross-platform implementation plan](10-implementation-plan.md): phased
    Windows/macOS delivery plan, shared C ABI core, synchronization gates, and CI.

## Normative language and precedence

MUST/MUST NOT identify interoperability or safety requirements. SHOULD identifies
a default that may be changed with a documented implementation reason. MAY is
optional. A proposed requirement is still normative *within this draft*; this
does not imply production readiness or a published Internet standard.

The wire definitions in documents 02-04 take precedence over narrative examples.
Document 05 defines media semantics; document 06 defines the local Windows ABI.
The numeric limits table in document 07 is the central limits reference. A
contradiction is a specification defect to fix before implementing that behavior,
not permission for each platform to select its own interpretation.

## Fixed v1 decisions

| Area | Decision |
| --- | --- |
| Discovery | mDNS with DNS-SD service `_ghostmedia._tcp.local.` |
| Server | Windows user-mode service advertises and accepts TCP |
| Client | Mac browses, connects, and coordinates stream lifecycle |
| Control | Length-prefixed UTF-8 JSON over mutually pinned TLS 1.3 over TCP |
| Media | Custom GMA/1 datagrams over unicast UDP, directional AES-256-GCM protected |
| Required audio | 48 kHz, stereo, signed 16-bit little-endian PCM, 5 ms packets |
| Optional audio | Explicitly advertised Opus stereo, 48 kHz clock, 10 ms packets |
| Network scope | One directly reachable peer; LAN first; no relay or NAT traversal |
| Routing | One active Mac audio subscriber per Windows service in v1 |
| Driver behavior | Device remains present and advances independently of consumers |
| Recovery | Fresh session, keys, stream IDs, and playout buffer after reconnect |
| Trust bootstrap | Bilateral local approval of full SPKI fingerprints via an independent channel; no TOFU |

A compressed profile is optional. An uncompressed implementation can conform to
v1. No implementation may silently substitute plaintext TCP, unauthenticated UDP,
audio over TCP, a different format, or an unadvertised capability.

## Standards used

The following primary references were checked while drafting. Their established
mechanisms are used where specified; GhostMedia's messages, policies, constants,
and state machines are project design choices.

- [RFC 6762: Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762)
- [RFC 6763: DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), especially section 7.5
- [RFC 8259: JSON](https://www.rfc-editor.org/rfc/rfc8259)
- [RFC 5116: Authenticated encryption interface](https://www.rfc-editor.org/rfc/rfc5116)
- [RFC 8085: UDP usage guidelines](https://www.rfc-editor.org/rfc/rfc8085)
- [RFC 6716: Opus](https://www.rfc-editor.org/rfc/rfc6716)
- [Microsoft: developing a WaveRT miniport](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/developing-a-wavert-miniport-driver)
- [Microsoft: SYSVAD sample](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/sample-audio-drivers)

Before release: validate the chosen TLS library's exporter and certificate-pin
support on both platforms, review the custom media protection composition,
complete the tests in document 09, and arrange service-name registration as
appropriate. The service name and ALPN token in this draft are project identifiers,
not assertions of an existing IANA registration.
