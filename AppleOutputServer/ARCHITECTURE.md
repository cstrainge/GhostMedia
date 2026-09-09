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
                                |               ^
                                v               |
                        GhostMediaCore   GhostMediaAppleSecurity
                                        (identity, trust, AES-GCM,
                                         TLS exporter boundary)

GhostMediaAppleHarness (deterministic Phase 1/2 CLI)
        |                       |
        v                       v
GhostMediaProtocolBridge   GhostMediaAppleSecurity
```

`GhostMediaCore` compiles the same C++ sources consumed by the Windows CMake
build. Its public surface is the C ABI in `shared/include/ghostmedia/gm_core.h`.

`GhostMediaProtocolBridge` owns Swift lifetime, buffer, string, and error mapping
around that C ABI. Other Swift targets should not call the raw C API directly.

`GhostMediaAppleSecurity` owns the persistent server ID and trust records,
provisional exportable CryptoKit identity storage, Ed25519 certificate
construction, CryptoKit AES-256-GCM, and the native TLS exporter adapter. The
current SDK can export TLS keying material but cannot create the non-exportable
Ed25519 `SecIdentity` required for a live Network.framework listener, so the
conformant identity and transport integration remain intentionally unimplemented.

`GhostMediaAppleCore` contains types describing the Apple host, application state,
and output-service boundary. It must not parse control JSON, construct media
packets, or duplicate protocol state transitions.

`GhostMediaAppleUI` contains reusable Apple UI. Views consume snapshots and send
user intent to an injected service. They do not own sockets, Keychain records,
audio units, or protocol state.

`GhostMediaMac` is the macOS composition root. It creates macOS-specific adapters
and injects them into shared layers. The current target contains the app shell and
shared-core version probe.

`GhostMediaAppleHarness` is the Phase 1/2 integration executable. It feeds
deterministic control and media fixtures through `GhostMediaProtocolBridge` and
prints the resulting typed values. Its `--phase2-vectors` mode checks identity,
exporter-context, and AES-GCM vectors. Its explicit
`--listen ... --allow-plaintext` mode provides the one-shot TCP endpoint required
by the first Windows probe. It has no live TLS, DNS-SD, UDP media, or audio path.

## Planned adapter targets

| Target | Responsibility | Expected portability |
| --- | --- | --- |
| `GhostMediaTransport` | DNS-SD advertisement, TCP/TLS listener, UDP, interface binding | Shared API with platform policy adapters |
| `GhostMediaAudio` | Jitter-to-output ring and audio device integration | Shared primitives; separate macOS/iOS output adapters |
| `GhostMediaDiagnostics` | Typed local metrics and privacy-safe support data | macOS and iOS |

The package graph points toward the shared contracts and protocol bridge. Platform
hosts may depend on adapters; shared core and UI never depend on a platform host.

## Adding the iOS host

Create a thin `GhostMediaIOS` application target that imports the existing shared
targets, then supplies iOS implementations for foreground/background lifecycle,
local-network permission, Keychain access, listener publication, route handling,
and audio-session behavior. It must not fork schemas, packet validation,
cryptography, or protocol state transitions.

When iOS cannot continue its listener or audio output under system lifecycle rules,
the host withdraws discovery and stops the active stream as required by the
protocol. The architecture permits an iOS host without assuming macOS lifecycle
behavior applies to it.

## Build boundaries

Swift Package Manager is the source-of-truth build graph for the shared modules and
command-line verification. A signed application can use a thin Xcode app target
that consumes the same local package. Signing, entitlements, capabilities, and
asset catalogs belong to application targets rather than shared libraries.
