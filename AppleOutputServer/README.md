# GhostMedia Apple output server

This directory is the home for macOS/iOS output-server code. Shared Swift
contracts, protocol bridging, tests, and reusable UI stay here; future platform
hosts supply their own lifecycle, identity, transport, and audio adapters.

Phase 1 integrates the deterministic shared core through the `GhostMediaCore`
Clang module. `GhostMediaProtocolBridge` converts accepted C ABI results into safe
Swift values, and `GhostMediaAppleHarness` exercises control framing and parsing,
audio profiles, media headers and nonces, and replay bookkeeping without
duplicating protocol schema logic in Swift.

Phase 2 adds `GhostMediaRuntime`, the same OpenSSL 3 userspace runtime consumed by
Windows. It owns Ed25519 identity/certificate operations, pinned mutual TLS 1.3,
TLS exporters, AES-256-GCM, and portable socket I/O. `GhostMediaAppleSecurity`
persists the server ID, PKCS#8 identity material, and trust records in the
device-local Keychain.

Build and test from the repository root:

```sh
xcrun swift build --product GhostMediaAppleHarness
xcrun swift test
xcrun swift run GhostMediaAppleHarness
xcrun swift run GhostMediaAppleHarness --phase2-vectors
xcrun swift run GhostMediaRuntimeTests
xcrun swift build --product GhostMediaMac
```

Run the one-shot pre-TLS listener for the Windows control probe:

```sh
xcrun swift run GhostMediaAppleHarness --listen 51837 --allow-plaintext
```

The shared runtime listener binds all IPv4 interfaces, prints the stable test server ID, accepts
one connection, validates and answers `session.hello`, `transport.bind`, and
`stream.open`, then exits. This mode is only for the first interoperability test;
it is not a conformant replacement for the Phase 2 TLS transport.

Run the Phase 3 secure command-line fixture instead when testing synthetic media:

```sh
xcrun swift run GhostMediaAppleHarness --listen 51837 --phase3-test
```

It performs pinned mutual TLS 1.3, exporter-derived AES-256-GCM path validation,
and receives eight synthetic PCM packets into a deterministic discard sink. The
paired Windows command is in [PHASE3_TEST.md](../WinDevice/PHASE3_TEST.md).

The CMake-built shared core, runtime, and C/C++ ABI tests remain available with:

```sh
cmake -S . -B out/build/macos -DGM_BUILD_WINDOWS=OFF -DGM_BUILD_TESTS=ON
cmake --build out/build/macos --target gm_core GhostMediaRuntime
ctest --test-dir out/build/macos --output-on-failure
```

The macOS SwiftUI target is still an application shell. Wiring the proven TLS
engine into the live listener,
DNS-SD, UDP media, and platform audio remain later-phase work. See
[ARCHITECTURE.md](ARCHITECTURE.md) for module ownership and
[INTEGRATION.md](INTEGRATION.md) for the Phase 1 contract.
