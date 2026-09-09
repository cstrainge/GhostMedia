# Apple output-server architecture

## Goals

- Build and test the Apple code without opening Xcode.
- Compile the authoritative portable C++ core directly into Apple products.
- Share orchestration, models, protocol bridging, and suitable SwiftUI views
  between macOS and iOS.
- Keep lifecycle, identity storage, listener policy, and audio behind explicit
  platform adapters.
- Keep platform audio callbacks independent from SwiftUI, networking, decoding,
  allocation, and locks.

## Current modules

```text
GhostMediaMac (thin macOS host)
        |
        v
GhostMediaAppleUI (shared SwiftUI composition)
        |                       |
        v                       v
GhostMediaAppleCore     GhostMediaProtocolBridge (safe Swift values)
        |                       |               |
        |                       v               v
        |               GhostMediaCore   GhostMediaAppleSecurity
        |                                       |
        +---------------------------------------v
                                    GhostMediaRuntime
                                    (OpenSSL TLS/identity/AES,
                                     TCP transport boundary)

GhostMediaAppleHarness (deterministic Phase 1/2 CLI)
        |                       |
        v                       v
GhostMediaProtocolBridge   GhostMediaAppleSecurity
        |                       |
        +-----------+-----------+
                    v
            GhostMediaRuntime
```

`GhostMediaCore` compiles the same C++ sources consumed by the Windows CMake
build. Its public surface is the C ABI in `shared/include/ghostmedia/gm_core.h`.

`GhostMediaProtocolBridge` owns Swift lifetime, buffer, string, and error mapping
around that C ABI. Other Swift targets should not call the raw C API directly.

`GhostMediaRuntime` is the shared C++ userspace runtime. It currently owns
portable TCP socket operations, OpenSSL TLS 1.3, pinned Ed25519 peer validation,
certificates, exporters, and AES-256-GCM. UDP transport will be added here rather
than in a platform host. It is separate from `GhostMediaCore` so deterministic
protocol logic remains free of I/O and third-party crypto dependencies.

`GhostMediaAppleSecurity` owns Apple Keychain persistence for the server ID,
PKCS#8 identity material, and trust records. Cryptographic operations delegate to
`GhostMediaRuntime`; Apple code does not maintain a second TLS or AES provider.

`GhostMediaAppleCore` contains types describing the Apple host, application state,
and output-service boundary. It must not parse control JSON, construct media
packets, or duplicate protocol state transitions.

`GhostMediaAppleUI` contains reusable Apple UI. Views consume snapshots and send
user intent to an injected service. They do not own sockets, Keychain records,
audio units, or protocol state.

`GhostMediaMac` is the macOS composition root. It creates macOS-specific adapters
and injects them into shared layers. `GhostMediaAppleCore` includes the DNS-SD
advertisement adapter for the authenticated listener; the host starts and stops it
with listener lifecycle. The current target otherwise contains the app shell and
shared-core version probe.

`GhostMediaAppleHarness` is the Phase 1/2 integration executable and Phase 3
command-line fixture. It feeds
deterministic control and media fixtures through `GhostMediaProtocolBridge` and
prints the resulting typed values. Its `--phase2-vectors` mode checks identity,
exporter-context, AES-GCM, and an in-memory pinned mutual-TLS 1.3 handshake. Its explicit
`--listen ... --allow-plaintext` mode provides the one-shot TCP endpoint required
by the first Windows probe. Its explicit `--listen ... --phase3-test` mode adds
pinned mutual TLS, exporter-derived AES-GCM UDP path validation, and an ordered
synthetic PCM discard sink using test-only identities. It has no DNS-SD or Apple
audio-output path.

## Planned adapter targets

| Target | Responsibility | Expected portability |
| --- | --- | --- |
| `GhostMediaAudio` | Jitter-to-output ring and audio device integration | Shared primitives; separate macOS/iOS output adapters |
| `GhostMediaDiagnostics` | Typed local metrics and privacy-safe support data | macOS and iOS |

The package graph points toward the shared contracts and protocol bridge. Platform
hosts may depend on adapters; shared core and UI never depend on a platform host.

## Adding the iOS host

Create a thin `GhostMediaIOS` application target that imports the existing shared
targets, then supplies iOS implementations for foreground/background lifecycle,
local-network permission, Keychain access, listener publication, route handling,
and audio-session behavior. Socket, TLS, identity, and media cryptography remain
in `GhostMediaRuntime`; the host must not fork schemas, packet validation,
cryptography, transport mechanics, or protocol state transitions.

When iOS cannot continue its listener or audio output under system lifecycle rules,
the host withdraws discovery and stops the active stream as required by the
protocol. The architecture permits an iOS host without assuming macOS lifecycle
behavior applies to it.

## Build boundaries

Swift Package Manager is the source-of-truth build graph for the shared modules and
command-line verification. A signed application can use a thin Xcode app target
that consumes the same local package. Signing, entitlements, capabilities, and
asset catalogs belong to application targets rather than shared libraries.
