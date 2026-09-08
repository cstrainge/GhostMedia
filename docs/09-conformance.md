# 09. Conformance and examples

## Required implementation checks

An implementation conforms to v1 only when it passes shared cross-platform tests:

1. DNS-SD publish/browse correctly resolves PTR/SRV/TXT/A/AAAA and ignores spoofed
   TXT identity after TLS pin mismatch.
2. Unknown, disabled, and mismatched identity keys fail mutual TLS; no TOFU path
   exists. ALPN mismatch, invalid certificate proofs, expired certificates, and
   invalid exporter context fail closed.
3. Control framing handles every TCP segmentation/coalescing pattern; rejects zero,
   oversized, invalid UTF-8, duplicate-key, and malformed JSON frames safely.
4. Every request/result/error/event schema above accepts valid cases and rejects
   wrong role/session/state/profile/port/ID types. Mutations are serial/idempotent
   only as specified.
5. UDP fixtures verify header big-endian fields, AAD exactness, nonce derivation,
   AES-GCM tags, replay-window behavior, path challenges, tuple checks, and rejection
   of bad lengths/magic/version/flags/reserved/session/stream/direction/epoch.
6. PCM fixtures verify byte order, interleaving, signed endpoints, packet length,
   timestamp progression, silence, loss concealment, late packet discard, and
   discontinuity flushing. Opus fixtures apply when capability is shipped.
7. Driver-bridge ABI tests verify service-SID open/attach authorization, rejection
   of arbitrary users/admin data-handle access, single-reader ownership, fixed-size
   IOCTL validation, read-only mappings, non-inheritable/non-writable mapping
   handles, odd/even interlocked commit publication, stale/duplicated handle epoch isolation,
   close/cancellation races, service death, PnP removal, and bridge reattach.
8. Fault tests kill/restart the Windows service or Apple output server, stop the Apple
   app, blackhole UDP, delay/reorder/
   duplicate packets, fill all queues, alter network interface/address/route/firewall
   profile, and change output route. An interface loss withdraws discovery, stops
   its bound stream, invalidates its path, and requires fresh discovery/TLS/path
   validation before media resumes. Windows playback remains present and driver
   callbacks do not wait.
9. Scheduling-pressure tests inject a 50 ms service pause, CPU saturation, page
   faults, logging pressure, endpoint reconfiguration, and delayed user-mode reads.
   They prove the 100 ms bridge and 40 ms send capacity remain bounded, freshness
   discard occurs at 50/20 ms respectively, timelines/counters/discontinuities are
   correct, and no wait, allocation, or network work occurs in the driver render
   path.
10. Latency tests report every component in the audio latency contract and validate
    the local-LAN objective only under its stated endpoint, route, and network
    preconditions. They label unavailable one-way latency and do not treat packet
    receipt as audible output.
11. Resource tests show queue/datagram/frame limits bound memory and that logs and
    diagnostic artifacts omit audio and secrets.
12. Authorization tests prove that an approved audio peer cannot begin media until
    the Apple output app acknowledges the visible indicator, that `Stop stream` ends
    media promptly, that revocation closes sessions, and that headless streaming
    requires explicit local enablement plus its required local audit record.
13. Server-identity tests prove first-run CSPRNG generation by the Apple output
    server, persistent reuse across its restart and network-name/address changes,
    non-advertisement before TLS,
    client rejection of an authenticated `server_id` mismatch, and controlled reset
    behavior after image-clone or explicit identity-reset simulation. They also prove
    startup fails closed when protected identity storage is unavailable and that a
    same-installation backup restore retains the ID without bypassing SPKI pinning.

Tests use deterministic fake clocks, seeded cryptographic test vectors only, and
separate production CSPRNG tests. Production keys/packets never become fixtures.

## Reference successful trace

```text
Win    mDNS browse -> Apple output-server record
Win    TLS 1.3 mutual-auth connect, ALPN ghostmedia/1
Win -> Apple  session.hello(id=1, udp_port=49152)
Apple -> Win  result(server_id, session_id, udp_port=51838, capabilities)
Win -> Apple  transport.bind(id=2, udp_port=49152)
Apple -> Win  result(path_state=bound)
Win -> Apple  stream.open(id=3, PCM 48k/stereo/240, target=30ms)
Apple -> Win  result(stream_id=1, key_epoch=1, path_state=probing)
Win => Apple  encrypted PATH_CHALLENGE; Apple => Win PATH_RESPONSE
Apple -> Win  event.path.validated
Win -> Apple  stream.start(id=4, stream_id=1)
Apple -> Win  result(first_media_timestamp="...") then event.stream.started
Win => Apple  protected GMA AUDIO every 5 ms
Apple => Win  protected FEEDBACK every 500 ms
Win -> Apple  stream.stop, stream.close, session.close
```

The trace is illustrative; every value is checked against the defined states and
wire formats. Receiving UDP audio before a completed start is a test failure even
if that audio would otherwise decrypt.

## Review gates before implementation milestones

Before driver work: review the local bridge ABI, service-SID/device ACL, mapping and
handle-lifetime model, real-time allocation audit plan, and Windows driver
signing/test environment. Before Mac work: validate
Core Audio callback threading, output route changes, key/certificate storage, and
platform mDNS/TLS exporter APIs. Before a networked prototype: independently review
the custom AEAD envelope and test vectors, then run interoperability capture tests
on IPv4, IPv6/link-local scope, Wi-Fi loss/reordering, and a manually addressed peer.

Before any public release: decide service-name registration, produce privacy and
permission UX, complete threat-model review, performance measurements, signed driver
installation/recovery testing, and an upgrade/compatibility policy. These are gates,
not proof that the proposed draft is production-ready.
