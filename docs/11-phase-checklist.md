# 11. Phase checklist

Status: working checklist for protocol draft 1.0-draft.1. This document tracks
implementation progress by phase and component. The normative protocol and
platform requirements remain in documents 01-09; the delivery order and phase
definitions come from [10. Cross-platform implementation plan](10-implementation-plan.md).

## Checklist legend

- [x] Implemented or prepared in the current repository.
- [ ] Not implemented yet, or requires validation on the owning platform.
- Items marked "partial" have an initial scaffold or proof point, but do not yet
  satisfy the phase exit criteria.

## Phase 0 - baseline and toolchains

Goal: make the protocol revision, supported architectures, reproducible builds,
and fixture ownership explicit.

### Components

- [x] Root CMake project.
- [x] Initial shared C ABI library scaffold.
- [x] Windows service scaffold.
- [ ] Swift package or Xcode wrapper for the Apple output-server app.
- [ ] Windows WDK driver stub and package skeleton.
- [ ] Fixture tooling and protocol change log.
- [ ] Header-size/schema linting.

### Shared core

- [x] ABI version and protocol version query surface.
- [x] Error/status registry scaffold.
- [ ] Fake clock interface.
- [ ] CSPRNG interface.
- [ ] Canonical fixture format.
- [ ] Protocol change-log workflow.

### Windows

- [x] MSVC/CMake build preset pinned for the current Windows environment.
- [x] Empty service target builds.
- [ ] Windows SDK/WDK requirements pinned in build docs or presets.
- [ ] Empty WDK driver project builds without installing a driver.
- [ ] TLS feasibility spike for Ed25519 leaf-only mutual TLS 1.3 and exporter output.

### Apple output server

- [x] Apple output-server handoff directory and integration notes.
- [x] Clang module map for Swift import of the shared C ABI.
- [ ] Apple toolchains pinned.
- [ ] Empty Apple CLI receiver imports and calls the C module.
- [ ] Apple TLS feasibility spike with Keychain identity storage and exporter output.

### Exit checks

- [x] Windows builds the core and service scaffold.
- [x] C ABI smoke test builds and passes on Windows.
- [ ] macOS builds the core stub.
- [ ] Swift calls a version function.
- [ ] Fixture reader round-trips one known fixture on both platforms.
- [ ] Both TLS spikes complete the exact v1 handshake and match exporter output.

## Phase 1 - deterministic protocol core

Goal: implement pure protocol behavior with no socket or device dependency.

### Components

- [x] Control frame parsing and encoding.
- [x] Bounded JSON validation for v1 control messages.
- [x] Closed-schema checks for requests, results, events, and errors.
- [x] Media header encode/decode helpers.
- [x] Nonce construction helpers.
- [x] Audio profile validation.
- [x] Replay-window bookkeeping.
- [x] Phase 1 protocol state graph for the Apple output-server control side.
- [x] Deterministic queue, jitter, and freshness policy calculations.
- [x] Timing calculations for v1 packet interval, playout target, timestamp window,
  bridge capacity, and send freshness.
- [x] Typed metrics surface for Phase 1 control/session counters.
- [x] Typed core action sink for Phase 1 control transitions.
- [x] Deterministic parser/state mutation and property smoke tests.

### Shared core

- [x] Validates revised roles: Windows `win-client` and Apple `apple-output-server`.
- [x] Validates revised media direction: `win_to_apple`.
- [x] Validates revised event set.
- [x] Rejects stale Mac-client and Windows-to-Mac assumptions.
- [x] Generates deterministic state/action traces through the C ABI.
- [x] Runs fixed-buffer packet-path budget checks.

### Windows

- [x] C++ tests exercise the shared core fixtures.
- [x] Windows control probe uses shared core parsing and framing.
- [x] Dedicated Windows conformance tests record typed core actions.

### Apple output server

- [ ] Swift CLI harness uses the shared C ABI without duplicating JSON semantics.
- [ ] Apple harness produces byte-identical frames and traces against Windows fixtures.

### Exit checks

- [x] Fragmented/coalesced frame behavior covered by shared tests.
- [x] Malformed JSON and stale schema assumptions rejected by shared tests.
- [x] Basic C ABI smoke coverage exists.
- [x] Duplicate ID and state idempotency tests.
- [x] Queue/profile/freshness edge tests.
- [x] Deterministic parser/state mutation and fixed-budget smoke tests.

## Phase 2 - identity, TLS adapters, and cryptographic vector lock

Goal: prove authenticated transport bytes before real networking.

### Components

- [ ] Crypto-layout module.
- [ ] TLS exporter adapter interface.
- [ ] Identity and trust adapter interfaces.
- [ ] Machine-readable vector corpus.
- [ ] AES-256-GCM provider adapter.
- [ ] Epoch lifecycle tests and vectors.
- [ ] Replay/rekey grace tests and vectors.

### Shared core

- [x] Header serialization helpers.
- [x] Nonce construction helpers.
- [x] Replay logic scaffold.
- [ ] Exporter-context construction.
- [ ] AAD construction.
- [ ] Key length and nonce length checks.
- [ ] AES-GCM call boundary.
- [ ] Positive and negative crypto vectors.

### Windows

- [ ] Client identity key generation/storage.
- [ ] Self-signed Ed25519 leaf certificate.
- [ ] Local trust records and revocation handling.
- [ ] TLS adapter enforcing leaf-only mutual authentication.
- [ ] TLS exporter output supplied to the shared core.

### Apple output server

- [ ] Persistent CSPRNG server ID.
- [ ] Output-server identity key generation/storage.
- [ ] Self-signed Ed25519 leaf certificate.
- [ ] Local trust records and revocation handling.
- [ ] TLS listener enforcing leaf-only mutual authentication.
- [ ] TLS exporter output supplied to the shared core.

### Exit checks

- [ ] Bad leaf, pin, revocation, and wrong peer are rejected.
- [ ] Windows and Apple exporter bytes match vectors.
- [ ] Altered header, AAD, ciphertext, or tag fails.
- [ ] Nonce uniqueness and replay edges are covered.
- [ ] No media key is available before an authorized stream.

## Phase 3 - first transport vertical slice

Goal: demonstrate secure Windows-to-Apple UDP audio without a virtual driver or
Core Audio output.

### Components

- [x] Partial: Windows pre-TLS control probe reaches `stream.open` against the Mac harness.
- [ ] Windows console control client and media sender.
- [ ] Apple CLI output server and media receiver.
- [ ] mDNS browse and advertisement adapters.
- [ ] TCP/TLS control transport adapters.
- [ ] UDP media transport adapters.
- [ ] Synthetic 48 kHz stereo PCM source.
- [ ] Deterministic discard sink.
- [ ] Capture trace tooling.
- [ ] Network fault injection tooling.

### Shared core

- [x] Control framing and schema validation used by the Windows probe.
- [x] Media header direction validation for path challenge/response.
- [ ] Full hello, bind, open, path challenge, start, feedback, rekey, stop, and close state flow.
- [ ] Interface-loss actions.
- [ ] Metrics emitted through typed actions.

### Windows

- [x] Pre-TLS framed TCP probe with pinned `server_id` support.
- [x] Local dry-run and loopback smoke coverage for the probe.
- [ ] Manual LAN addressing flow documented as authorized test mode.
- [ ] DNS-SD browse limited to an explicitly enabled private interface.
- [ ] TLS-backed control connection.
- [ ] UDP path validation sender.
- [ ] Synthetic PCM packetizer and pacer.
- [ ] Client-side connection limits.
- [ ] Sender-initiated rekey.

### Apple output server

- [x] Partial: one-shot Mac listener can satisfy the first control probe.
- [ ] CLI output server accepts the real TLS control connection.
- [ ] Trust approval path for the Windows client.
- [ ] UDP receive, decrypt, replay, reorder, and metrics path.
- [ ] Deterministic discard sink.
- [ ] Receiver loss and interface-loss behavior.

### Exit checks

- [x] Pre-TLS Windows-to-Mac control/framing probe reaches `stream.open`.
- [ ] Loopback secure transport trace.
- [ ] Two-host IPv4 trace.
- [ ] IPv6 link-local trace with scope handling.
- [ ] Wi-Fi loss, reorder, duplicate, and flood tests.
- [ ] Windows-initiated path expiry and retry.
- [ ] Sender-initiated rekey.
- [ ] Service restart and receiver loss tests.
- [ ] Simulated 30-minute epoch rollover.
- [ ] Local stop, revoke, and headless-mode checks.

## Phase 4 - Apple platform-audio output server

Goal: replace the discard sink with reliable audible playback.

### Components

- [ ] Swift app shell.
- [ ] `AppleAudioOutput` adapter.
- [ ] Output AudioUnit.
- [ ] Preallocated PCM ring.
- [ ] System-output-route monitor.
- [ ] Route-change discontinuity handling.
- [ ] Feedback worker.

### Shared core

- [ ] Decoded PCM queue/pull API with no Core Audio types.
- [ ] Jitter metrics.
- [ ] Output-underflow reporting.
- [ ] Output-running state reporting.
- [ ] Route-change discontinuity interface.

### Windows

- [ ] Continue Phase 3 synthetic source unchanged.
- [ ] Display feedback as telemetry only.

### Apple output server

- [ ] Allocate rings before stream start.
- [ ] Keep callback limited to ring read and silence fill.
- [ ] Keep resampling, logging, Swift allocation, locks, and network work off the callback.
- [ ] Observe current Apple system route only.
- [ ] Flush and reprime on route or sample-rate change.

### Exit checks

- [ ] Golden tone and silence playback.
- [ ] System-route and sample-rate changes.
- [ ] Headset removal.
- [ ] Forced underflow.
- [ ] 15 ms, 30 ms, and 120 ms target latency runs.
- [ ] Drift simulation.
- [ ] Sleep/wake and app restart.
- [ ] No Apple-attached device inventory or route-selection control exposed to Windows.

## Phase 5 - Windows userspace capture pipeline

Goal: prove service conversion, pacing, freshness, and failure isolation using a
simulated bridge before kernel integration.

### Components

- [ ] Capture worker.
- [ ] Converter and resampler.
- [ ] Packet pacer.
- [ ] Bounded bridge simulator.
- [ ] Service supervisor.
- [ ] Windows configuration API.
- [ ] Windows configuration UI.

### Shared core

- [ ] Reuse profile, freshness, packetization, timestamp, and discontinuity decisions.
- [ ] Keep Windows audio types out of the ABI.

### Windows

- [ ] Simulate fixed PCM producer formats: 44.1, 48, and 96 kHz.
- [ ] Simulate mono, stereo, and surround input.
- [ ] Implement documented downmix behavior.
- [ ] Preserve 100 ms bridge queue and 50 ms freshness limit.
- [ ] Preserve 40 ms send queue and 20 ms freshness limit.
- [ ] Prove no TLS or socket work runs on the producer path.

### Apple output server

- [ ] Run Phase 4 unchanged.
- [ ] Regress conversion and discontinuity behavior.

### Exit checks

- [ ] Golden conversion and downmix files.
- [ ] 50 ms pause scenario.
- [ ] CPU saturation scenario.
- [ ] Blocked network scenario.
- [ ] Queue overflow scenario.
- [ ] Simulated bridge restart.
- [ ] Impulse-based latency report.

## Phase 6 - Windows virtual render driver and bridge

Goal: implement the persistent virtual endpoint without changing proven network or
Apple-device behavior.

### Components

- [ ] WaveRT virtual render driver.
- [ ] INF and package.
- [ ] Service-SID bridge IOCTLs.
- [ ] Fixed section and event bridge.
- [ ] PnP and power handling.
- [ ] ETW instrumentation.
- [ ] Driver Verifier harness.

### Shared core

- [ ] No shared-core code in the driver.
- [ ] Userspace continues using the existing shared core unchanged.

### Windows driver and device

- [ ] Preallocated blocks.
- [ ] One authorized service-SID handle.
- [ ] Read-only service mapping.
- [ ] Odd/even interlocked commit publication.
- [ ] Epoch invalidation on close, service death, PnP removal, and format change.
- [ ] No allocation, network, or wait in the render path.

### Windows userspace

- [ ] Replace bridge simulator with bridge client.
- [ ] Discard conversion/send queues on epoch change.
- [ ] Initiate documented discontinuity on epoch change.

### Apple output server

- [ ] No redesign from Phase 4/5 receiver behavior.
- [ ] Verify stop, discontinuity, and reprime behavior.
- [ ] Never play stale audio after bridge reset.

### Exit checks

- [ ] Driver Verifier.
- [ ] Applicable WDK/HLK tests.
- [ ] PnP and sleep/resume tests.
- [ ] Service kill/restart tests.
- [ ] Unauthorized attach tests.
- [ ] Stale epoch and handle race tests.
- [ ] 24-hour soak.
- [ ] Playback with no Apple output server, no network, and blocked UDP.

## Phase 7 - release hardening

Goal: produce signed, observable, maintainable platform releases.

### Components

- [ ] Installer and updater.
- [ ] Signed driver package.
- [ ] Configuration and trust UI.
- [ ] Privacy and permission flows.
- [ ] Support bundle.
- [ ] Crash handling.
- [ ] Release automation.

### Shared core

- [ ] Freeze ABI and protocol revision.
- [ ] Publish compatibility policy.
- [ ] Run fuzzing and sanitizers.
- [ ] Version fixtures.
- [ ] Test persisted-state compatibility.

### Windows

- [ ] Signing and distribution.
- [ ] Firewall lifecycle.
- [ ] Service recovery.
- [ ] Rollback.
- [ ] ETW and event policy.
- [ ] Upgrade, uninstall, and diagnostics excluding media and keys.

### Apple output server

- [ ] Signing and notarization.
- [ ] Keychain migration.
- [ ] Launch and relaunch behavior.
- [ ] Permission and output-device UX.
- [ ] Support bundles.
- [ ] Supported-version upgrade tests.

### Exit checks

- [ ] Install, upgrade, downgrade, and uninstall.
- [ ] Revocation.
- [ ] Interface and firewall changes.
- [ ] Soak and leak testing.
- [ ] Fuzz regression.
- [ ] Security review.
- [ ] Signed-package validation.
- [ ] Cross-version matrix.

## Synchronization gates

- [ ] G0 protocol: schemas, byte order, limits, errors, and state graph agree.
- [ ] G1 ABI: ownership, layout, versioning, thread rules, and error/action mapping agree.
- [ ] G2 crypto/identity: SPKI, server ID, exporter context, directions, epochs,
  nonce/AAD, tags, and path failure agree.
- [ ] G3 lifecycle: hello, bind, open, path, start, stop, rekey, close, and
  idempotency agree.
- [ ] G4 timing: timestamps, drops, discontinuity, prime, concealment, and drift
  units agree.
- [ ] G5 transport: mDNS exposure, TLS rejection, socket tuple, and interface-loss
  behavior agree.
- [ ] G6 audio: PCM conversion, channel order, callback ring, feedback, and route
  changes agree.
- [ ] G7 bridge: service SID, descriptor, epoch, memory ordering, and PnP teardown
  agree.

## Current integration checkpoint

- [x] Windows `GhostMediaWinControlProbe` built with the MSVC preset.
- [x] Windows probe dry-run passes.
- [x] Shared core C++ and C ABI tests pass on Windows.
- [x] Real Mac one-shot listener accepted the Windows pre-TLS control probe.
- [x] Probe reached `stream.open` with server ID
  `01234567-89ab-cdef-0123-456789abcdef`.
- [ ] TLS/exporter adapter replaces the plaintext probe path.
- [ ] AES-GCM media key/vector lock completed before UDP media is sent.
- [ ] Secure UDP path challenge/response completed.
- [ ] Synthetic PCM packets sent and received over protected UDP.
