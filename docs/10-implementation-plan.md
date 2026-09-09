# 10. Cross-platform implementation plan

Status: proposed plan for protocol draft 1.0-draft.1. Documents 01-09 remain the
wire and security authority. Resolve contradictions in those documents before code
depends on a behavior.

## Delivery order

Build a portable, deterministic protocol core first. Prove it with a Windows
userspace synthetic source and an Apple command-line synthetic receiver. Then add
Apple platform audio output, then the Windows driver bridge. This prevents a driver or audio
callback problem from concealing a protocol defect.

```text
shared core + fake transport
  -> Windows control client/media sender <=> Apple CLI output server/media receiver
  -> Windows control client/media sender <=> Apple platform-audio output server/media receiver
  -> Windows WaveRT bridge <=> control client/media sender <=> Apple output server/media receiver
```

Microphone and camera work begins only after the render path passes Phase 6.

## Ownership boundaries

| Area | Owns | Must not own |
| --- | --- | --- |
| Shared core | Wire schema, serialization, packet validation, protocol states, crypto input construction, replay/jitter/queue policy, timing arithmetic, metrics | Sockets, TLS engine, threads, UI, device APIs |
| Windows userspace | Service, Winsock/TLS/DNS-SD browse adapters, driver bridge client, conversion/pacing workers, Control Panel configuration | Kernel render timing or a protocol fork |
| Windows driver | WaveRT endpoint, render clock, bounded bridge, PnP lifecycle | Network, TLS, codecs, mDNS, UI |
| macOS/iOS userspace | Apple output app, trust store, DNS-SD advertisement, socket/TLS listener adapters, receiver workers, configuration | Protocol parsing or platform audio callback work |
| macOS Core Audio / AVFoundation | Core Audio output callback, output route/rate handling; future AVFoundation capture | Transport, TLS, wire state, encryption |

V1 macOS output uses Core Audio. The callback only pulls decoded PCM from a
preallocated ring and supplies silence on underflow. Packet receive, decrypt,
decode, resampling, logging, Swift allocation, and locks stay off that callback.

## Shared-core architecture and C ABI

Implement the core in modern C++ as a static library on each platform. Export a
narrow C ABI through opaque handles. Windows C++ uses a small RAII wrapper; Swift
imports the C header through a Clang module map and uses a Swift ownership wrapper.
Never expose C++ classes, STL containers, exceptions, templates, Objective-C, or
compiler-specific layout across the boundary.

The core owns: control framing and closed-schema validation; control and media state
machines; binary header/AAD/nonce/exporter-context construction; AES-GCM calls via
a narrow crypto provider interface; replay windows; bounded jitter and PCM queues;
profile validation; drift/timing calculations; typed metrics; and state actions.
It does not own sockets, TLS, mDNS, platform key stores, CSPRNG, device clocks,
audio codecs/resamplers, threads, or filesystems. Platform adapters provide those
dependencies and execute typed core actions such as send-control, send-UDP,
Windows-sender path challenge, stop stream, and emit event.

```c
typedef struct gm_session gm_session;
typedef struct gm_stream gm_stream;
typedef struct { const uint8_t *data; size_t size; } gm_bytes;
typedef enum { GM_OK, GM_BAD_ARGUMENT, GM_BAD_MESSAGE, GM_STATE_CONFLICT,
               GM_LIMIT_EXCEEDED, GM_BUFFER_TOO_SMALL, GM_UNAUTHORIZED } gm_status;

gm_status gm_session_create(const gm_session_config *, gm_session **out);
void gm_session_destroy(gm_session *);
gm_status gm_control_ingest(gm_session *, gm_bytes, uint64_t now_ns, gm_action_sink *);
gm_status gm_control_encode(gm_session *, const gm_control_command *, gm_mut_bytes,
                            size_t *written);
gm_status gm_stream_ingest_datagram(gm_stream *, gm_bytes,
                                    const gm_packet_context *, uint64_t now_ns,
                                    gm_action_sink *);
gm_status gm_stream_next_playout(gm_stream *, uint64_t now_ns, gm_pcm_buffer *,
                                 gm_playout_result *);
```

Every ABI structure begins with `struct_size` and `abi_version`. Use fixed-width
types, caller-owned spans/buffers, explicit `GM_BUFFER_TOO_SMALL`, status enums,
and no exception crossing. New fields append only. The core retains neither a
callback nor a supplied buffer after the call returns. Action callbacks MUST NOT
reenter the same session or stream handle. The caller serializes each handle on one
executor, preserves core action order when queueing platform work, and reports any
asynchronous completion through a later explicit core call. Handles are thread-affine
unless their header says otherwise. Packet and real-time entry points must work from
fixed caller buffers without allocation.

TLS remains platform code. After it validates the leaf-only mutual TLS connection,
the adapter supplies only required exporter output/material to the core. The core
never receives a private key, certificate, or TLS handle.

## Synchronization gates

| Gate | Both sides must agree on | Evidence before proceeding |
| --- | --- | --- |
| G0 protocol | Schemas, byte order, limits, errors, state graph | Tagged protocol revision/change log |
| G1 ABI | Ownership, struct layout/versioning, thread rules, action/error mapping | `gm_core.h` and ABI tests in C++ and Swift |
| G2 crypto/identity | SPKI form, server ID lifecycle, exporter context, directions, epoch/sequence, nonce/AAD, tags | Positive and negative machine-readable vectors |
| G3 lifecycle | hello/bind/open/path/start/stop/rekey/close and idempotency | Generated state-table tests |
| G4 timing | timestamps, drops, discontinuity, prime, concealment, drift units | Deterministic fake-clock traces |
| G5 transport | mDNS exposure, TLS rejection, socket tuple, interface loss | Two-host integration traces |
| G6 audio | PCM/channel conversion, callback ring, feedback, route changes | Golden PCM fixtures and hardware report |
| G7 bridge | Service SID, descriptor, epoch, memory ordering, PnP teardown | Windows driver test report |

Changes after G2 regenerate vectors. Changes after G1 require ABI-major versioning
unless they only append fields covered by `struct_size`. No platform workaround may
alter a shared core state decision locally.

## Phase 0 — baseline and toolchains

**Goals:** make the protocol revision, supported architectures, reproducible builds,
and fixture ownership explicit.

**Components:** root CMake project; empty C ABI library; Swift package/Xcode wrapper;
Windows service and WDK driver stubs; fixture tooling.

**Shared core:** define error registry, ABI policy, fake clock/CSPRNG interfaces,
fixture format, protocol change log, and header-size/schema linting.

**Windows:** pin MSVC, SDK, WDK, CMake/Ninja; compile empty service/driver projects.
Do not install a driver. Build a TLS feasibility spike that creates the exact Ed25519
leaf, performs mutually authenticated TLS 1.3, rejects system roots/extra chains,
and exports the required context-bound secret.

**macOS/iOS:** pin the Apple toolchains; import the empty C module from an Apple
output-server CLI receiver.
Run the same TLS feasibility spike with Keychain identity storage and the intended
Network.framework or lower-level TLS adapter.

**Synchronization:** satisfy G0. Both owners tag the same protocol revision.

**Exit tests:** Windows and macOS build the core stub; Swift calls a version function;
the fixture reader round-trips one known fixture; the two TLS spikes complete the
exact v1 handshake and produce identical exporter test output.

**Risks/traps:** WDK drift, developer-local SDK paths, C++ ABI leaking into Swift,
TLS APIs that cannot enforce the required policy, and hand-edited generated vectors.

**Deliverable:** reproducible empty builds and ABI skeleton.

## Phase 1 — deterministic protocol core

**Goals:** implement pure protocol behavior with no socket or device dependency.

**Components:** `control`, `media`, `schema`, `state`, `limits`, `time`, `metrics`,
and test support.

**Shared core:** implement frame parsing, bounded JSON validation, typed messages,
state graph, profiles, limits, replay bookkeeping, timestamps, jitter decisions, and
typed actions. Inject time and random sources. Construct exact header/AAD/nonce bytes
but leave crypto invocation behind an adapter until Phase 2.

**Windows:** C++ console harness feeds fixtures and records actions.

**macOS:** equivalent Swift CLI harness through C ABI; no duplicated JSON semantics.

**Synchronization:** satisfy G1 and G3. Both harnesses produce byte-identical control
frames and action/state traces for valid and invalid inputs.

**Exit tests:** fragmentation/coalescing, malformed JSON, duplicate IDs, closed
schemas, state idempotency, queues, profile limits, property tests, and parser/state
fuzzing with allocation/time budgets.

**Risks/traps:** platform JSON parser differences, `u64` through Swift JSON numbers,
allocation on packet paths, unknown-field acceptance, callback reentry.

**Deliverable:** portable conformance binary with no audio/network dependencies.

## Phase 2 — identity, TLS adapters, and cryptographic vector lock

**Goals:** prove authenticated transport bytes before real networking.

**Components:** crypto-layout module, TLS-exporter adapters, identity/trust adapters,
and vector corpus.

**Shared core:** own exporter-context construction, key/nonce/AAD length checks,
header serialization, replay logic, and epoch lifecycle. Use a vetted AES-256-GCM
provider through a narrow interface; do not implement TLS/certificate parsing. The
first shipped implementation advertises PCM only. Opus remains disabled until a
pinned shared decoder/PLC implementation or byte-identical codec-adapter contract
passes golden decode and loss-concealment fixtures on both platforms.

**Windows:** client identity key, self-signed Ed25519 leaf, local trust records, and
a TLS adapter that enforces the exact leaf-only mutual-auth/exporter policy.

**macOS/iOS:** output-server identity key, self-signed Ed25519 leaf, persistent
CSPRNG server ID, trust records, and a TLS listener adapter. If platform TLS APIs
cannot expose the mandated validation/exporter behavior, use a vetted lower-level TLS
library behind the same interface; never weaken the protocol to fit an API. The iOS
implementation must withdraw discovery and stop streams when it cannot remain active.

**Synchronization:** satisfy G2. Publish vectors for peer ID, server-ID encoding and
mismatch handling, exporter input, epoch, direction, nonce, header, AAD, ciphertext,
tag, replay edges, and path failure.
Each side must run the other side's vectors.

**Exit tests:** bad leaf/pin/revocation, exporter match, altered header/tag/ciphertext,
nonce uniqueness, random-sequence edges, replay/rekey grace, and no key before an
authorized stream.

**Risks/traps:** system-root fallback, TLS tickets, DER/SPKI confusion, nonce reuse,
certificate shortcuts, and test-key leakage in logs.

**Deliverable:** locked vectors and mutually validated TLS adapters.

## Phase 3 — first transport vertical slice

**Goals:** demonstrate secure Windows-to-Apple UDP audio without a virtual driver or
Core Audio output.

**Components:** Windows console control client/media sender, macOS CLI output
server/media receiver, mDNS/TCP/TLS/UDP adapters, synthetic PCM source/sink.

**Shared core:** drive hello, bind, stream open, Windows-to-Apple path challenge,
start with a Windows source-timestamp boundary, feedback, sender-initiated rekey,
stop, close, interface-loss actions, and metrics. Adapters transmit core bytes
unchanged.

**Windows:** browse configured Apple servers only on an explicitly enabled private
interface. Generate 48 kHz stereo sine/silence PCM, packetize through core, and
enforce client-side connection limits. No driver code.

**macOS:** advertise or accept a manually configured Windows control client, use
preapproved trust, decrypt/reorder through core, print metrics, and drain decoded
PCM into the current local system-output route or a deterministic discard sink.

**Synchronization:** satisfy G4 and G5 with captured successful/failed traces;
agree on mDNS privacy, tuple/interface selection, reconnect, and timestamp inputs.

**Exit tests:** loopback, two-host IPv4, IPv6 link-local scope, Wi-Fi loss/reorder/
duplicate injection, TLS/UDP flood, Windows-initiated path expiry/retry,
sender-initiated rekey, service restart, receiver loss, interface loss, simulated
30-minute epoch rollover, indicator
acknowledgement, local stop/revoke, and explicitly enabled headless mode.

**Risks/traps:** testing only localhost, wrong IPv6 scope, socket source address
drift, mDNS API differences, and transport threads calling future callback code.

**Deliverable:** repeatable two-machine command-line demo with capture traces. This
is the first required end-to-end vertical slice.

## Phase 4 — Apple platform-audio output server

**Goals:** replace the discard sink with reliable audible playback.

**Components:** Swift app shell, `AppleAudioOutput`, output AudioUnit, preallocated
PCM ring, system-output-route monitor. V1 has no GhostMedia-specific output-device
selector and exposes no Apple-attached device inventory to Windows.

**Shared core:** expose decoded PCM queue/pull, jitter metrics, output-underflow,
output-running, and route-change discontinuity interfaces without Core Audio types.

**Windows:** continue the synthetic source; display feedback only as telemetry.

**macOS:** allocate rings before start, do ring read/silence fill only in callback,
resample off callback, and send feedback from a worker. Observe the current Apple
system route only; flush/reprime on local route or sample-rate change.

**Synchronization:** satisfy G6: confirm PCM conversion/channel order,
`rendered_media_timestamp`, feedback semantics, underflow, and discontinuity rules.

**Exit tests:** golden tone/silence, system-route/rate changes, headset removal,
forced underflow, 15/30/120 ms targets, drift simulation, sleep/wake, and app
restart. Prove that no Apple-attached device inventory or route-selection control is
exposed over GhostMedia.

**Risks/traps:** Swift allocation or locks in the callback, callback/network time
confusion, route notification races, and automatic system-route switching.

**Deliverable:** Apple output-server app plays synthetic Windows audio through its
system-default route and reports local state.

## Phase 5 — Windows userspace capture pipeline

**Goals:** prove service conversion, pacing, freshness, and failure isolation using
a simulated bridge before kernel integration.

**Components:** capture worker, converter/resampler, packet pacer, bounded bridge
simulator, service supervisor, Windows configuration API/UI.

**Shared core:** reuse profile, freshness, packetization, timestamp, and
discontinuity decisions; add no Windows audio types to the ABI.

**Windows:** simulate fixed PCM producer formats (44.1/48/96 kHz, mono/stereo/
surround), use documented downmix, preserve 100 ms bridge/50 ms freshness and 40 ms
send/20 ms freshness, and prove no TLS/socket work on the producer path.

**macOS:** use Phase 4 unchanged with conversion/discontinuity regressions.

**Synchronization:** reconfirm G4/G6: timestamps are assigned after conversion;
bridge/sender drops yield the documented receiver behavior.

**Exit tests:** golden conversion/downmix files, 50 ms pause, CPU saturation, blocked
network, queue overflow, simulated bridge restart, and impulse-based latency report.

**Risks/traps:** timestamping pre-conversion frames as 48 kHz, per-packet allocation,
priority starvation, and buffering that hides latency.

**Deliverable:** service streams simulated real-format source to audible Apple output.

## Phase 6 — Windows virtual render driver and bridge

**Goals:** implement the persistent virtual endpoint without changing proven network
or Apple-device behavior.

**Components:** WaveRT virtual render driver, INF/package, service-SID bridge IOCTLs,
fixed section/event, PnP/power handling, ETW, Driver Verifier harness.

**Shared core:** none in the driver. Userspace uses the existing core unchanged.

**Windows driver/device:** implement document 06 precisely: preallocated blocks;
one authorized service-SID handle; read-only service mapping; odd/even interlocked
commit publication; epoch invalidation on close, service death, PnP removal, and format
change; no allocation, network, or wait in the render path.

**Windows userspace:** replace simulator with bridge client. On epoch change,
discard conversion/send queues and initiate documented discontinuity.

**Apple output server:** no redesign; run the same receiver/fixture regressions.

**Synchronization:** satisfy G7. Freeze descriptor, memory ordering, and epoch
semantics. Apple receiver verifies only visible effect: stop/discontinuity/reprime, never stale
audio.

**Exit tests:** Driver Verifier, applicable WDK/HLK tests, PnP, sleep/resume, service
kill/restart, unauthorized attach, stale epoch/handle races, 24-hour soak, playback
with no Apple output server, no network, or blocked UDP.

**Risks/traps:** wrong IRQL, pageable render path, weak DACL, section reuse, treating
service availability as device availability, and driver installation recovery.

**Deliverable:** selectable GhostMedia Speakers endpoint that remains stable when all
downstream components fail.

## Phase 7 — release hardening

**Goals:** produce signed, observable, maintainable platform releases.

**Components:** installer/updater, signed driver package, configuration/trust UI,
privacy/permissions, support bundle, crash handling, release automation.

**Shared core:** freeze ABI/protocol revision, publish compatibility policy, run
fuzzing/sanitizers, version fixtures, and test persisted-state compatibility.

**Windows:** signing/distribution, firewall lifecycle, service recovery, rollback,
ETW/event policy, upgrade/uninstall and diagnostics that exclude media/keys.

**macOS:** signing/notarization, Keychain migration, launch/relaunch, permission and
output-device UX, support bundles, and supported-version upgrade tests.

**Synchronization:** repeat G0-G7 on release candidates. Both sides carry matching
protocol/ABI versions and reject unsupported peers safely.

**Exit tests:** install/upgrade/downgrade/uninstall, revocation, interface/firewall
changes, soak/leak, fuzz regression, security review, signed-package validation,
and cross-version matrix.

**Risks/traps:** stale driver/service pairs, identity leakage in support logs, public
firewall exposure, and advertising future microphone/camera capabilities early.

**Deliverable:** release candidate with reproducible CI evidence and support docs.

## Repository and build strategy

```text
GhostMedia/
  docs/
  protocol/{vectors,schemas,traces}/
  shared/{include/ghostmedia,core,crypto,test_support,tests}/
  WinDevice/{service,bridge_client,driver,installer,tests}/
  AppleOutputServer/{GhostMediaCore,GhostMediaApp,AudioOutput,tests}/
  tools/{vector_gen,packet_trace,network_fault_injector}/
  cmake/  .github/workflows/
```

Use CMake presets for shared core and Windows service. Build the WDK driver in a
Windows-only preset/solution that consumes generated headers but never links the
core. Build the Swift wrapper/app through SwiftPM or Xcode, statically linking the
platform-built core and importing `gm_core.h` through a module map. Pin dependencies,
generate an SBOM, and keep crypto, JSON validation, and C/C++ runtime dependencies
small. Platform TLS, keys, DNS-SD, sockets, and audio frameworks remain adapters.

### Final build artifacts

Every build or packaging workflow that produces an inspectable final artifact
MUST copy it into the repository-root `dist/` directory before reporting success.
This applies to the signed macOS application, Windows userspace service/helpers,
Windows driver and driver package, and every test executable used for manual or
cross-host validation. Intermediate compiler output remains in platform build
directories; `dist/` is the single, predictable handoff location for the artifacts
that a developer, test operator, or release reviewer needs to inspect or run.

Keep `dist/` flat so every final artifact is visible in one place. Filenames MUST
include the platform and architecture where that avoids ambiguity:

```text
dist/
  GhostMedia-macos-arm64.app
  GhostMediaWinService-windows-x64.exe
  GhostMediaWinDriver-windows-x64.sys
  GhostMediaWinDriver-windows-x64.zip
  GhostMediaAppleHarness-macos-arm64
  GhostMediaWinControlProbe-windows-x64.exe
  manifest-macos-arm64.json
  manifest-windows-x64.json
```

Each packaging workflow SHOULD place a manifest alongside its artifacts recording
the source revision, build configuration, platform/architecture, build time, and
checksums. A workflow MUST stage into a temporary directory and publish its own
artifacts into `dist/` only after the build and associated tests pass; it MUST NOT
delete or overwrite artifacts belonging to another platform or configuration.

| CI lane | Environment | Required checks |
| --- | --- | --- |
| Core fast | Windows, macOS, optional Linux | Build, unit, ABI, vectors, state traces |
| Core hostile | Windows and macOS | Fuzz/property, replay/path/limit, sanitizers where supported |
| Windows control client | Windows | TLS/UDP/DNS-SD browse and simulated-bridge fault tests |
| Windows driver | Self-hosted Windows lab | WDK build, Verifier, controlled install, bridge races |
| Apple output server | macOS/iOS lab | Swift ABI, platform-audio mocks, system-route tests |
| Two-host integration | Windows + Apple-device lab | Discovery, TLS, IPv4/IPv6, Wi-Fi faults, rekey, latency |
| Release | Both | Signed artifacts, upgrade/uninstall, SBOM, regression |

Hosted CI cannot prove driver installation, multicast, Wi-Fi loss, hardware route,
or IPv6 link-local behavior. Maintain a controlled Windows/Apple-device test lab and archive
protocol version, vector hash, ABI version, build IDs, and results for each release.

## First end-to-end slice acceptance criteria

Phase 3 is the first slice: the Windows control client/media sender generates 48 kHz
stereo PCM and sends it through the shared core over mutual TLS/TCP and protected UDP
to an Apple CLI output server/media receiver that validates, decrypts, reorders, and
drains it into a deterministic discard sink.

1. Discovery is limited to an explicitly enabled private interface, or manual LAN
   addressing is explicitly authorized.
2. Each side rejects unapproved, malformed, revoked, or wrong-pinned peers before
   exposing stream state or accepting media.
3. The successful trace covers hello, bind, open, Windows-to-Apple path
   challenge/response, Windows source-timestamp start, feedback, sender-initiated
   rekey, stop, and close with matching captured bytes.
4. Loss, reorder, duplication, bad tags, replay, interface loss, receiver loss, and
   service restart remain bounded and follow documented state/error behavior.
5. Windows C++ and macOS Swift harnesses match every vector and fake-clock trace.

Only after this slice passes should Apple platform output and the Windows driver be added.
