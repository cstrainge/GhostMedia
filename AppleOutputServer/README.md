# GhostMedia Apple output server

This directory is the home for macOS/iOS output-server code. Shared Swift
contracts, protocol bridging, tests, and reusable UI stay here; future platform
hosts supply their own lifecycle, identity, transport, and audio adapters.

Phase 1 integrates the deterministic shared core through the `GhostMediaCore`
Clang module. `GhostMediaProtocolBridge` converts accepted C ABI results into safe
Swift values, and `GhostMediaAppleHarness` exercises control framing and parsing,
audio profiles, media headers and nonces, and replay bookkeeping without
duplicating protocol schema logic in Swift.

Phase 2 adds `GhostMediaAppleSecurity`, which provides a persistent server ID,
Keychain-backed trust records, a provisional exportable CryptoKit identity, a
self-signed Ed25519 leaf-certificate builder, an AES-256-GCM provider, and the
Network.framework TLS-exporter boundary. The conformant non-exportable identity
and native live TLS listener remain pending because the current Apple Security
API does not expose a supported way to create an Ed25519 `SecIdentity` for
Network.framework.

Build and test from the repository root:

```sh
xcrun swift build --product GhostMediaAppleHarness
xcrun swift test
xcrun swift run GhostMediaAppleHarness
xcrun swift run GhostMediaAppleHarness --phase2-vectors
xcrun swift build --product GhostMediaMac
```

Run the one-shot pre-TLS listener for the Windows control probe:

```sh
xcrun swift run GhostMediaAppleHarness --listen 51837 --allow-plaintext
```

The listener binds all IPv4 interfaces, prints the stable test server ID, accepts
one connection, validates and answers `session.hello`, `transport.bind`, and
`stream.open`, then exits. This mode is only for the first interoperability test;
it is not a conformant replacement for the Phase 2 TLS transport.

The CMake-built shared core and C/C++ ABI tests remain available with:

```sh
cmake -S . -B out/build/macos -DGM_BUILD_WINDOWS=OFF -DGM_BUILD_TESTS=ON
cmake --build out/build/macos --target gm_core gm_core_tests gm_core_c_abi_tests
ctest --test-dir out/build/macos --output-on-failure
```

The macOS SwiftUI target is still an application shell. Live TLS networking,
DNS-SD, UDP media, and platform audio remain later-phase work. See
[ARCHITECTURE.md](ARCHITECTURE.md) for module ownership and
[INTEGRATION.md](INTEGRATION.md) for the Phase 1 contract.
