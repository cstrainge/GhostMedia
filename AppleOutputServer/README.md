# GhostMedia Apple output server

This directory is the home for macOS/iOS output-server code. Shared Swift
contracts, protocol bridging, tests, and reusable UI stay here; future platform
hosts supply their own lifecycle, identity, transport, and audio adapters.

Phase 1 integrates the deterministic shared core through the `GhostMediaCore`
Clang module. `GhostMediaProtocolBridge` converts accepted C ABI results into safe
Swift values, and `GhostMediaAppleHarness` exercises control framing and parsing,
audio profiles, media headers and nonces, and replay bookkeeping without
duplicating protocol schema logic in Swift.

Build and test from the repository root:

```sh
xcrun swift build --product GhostMediaAppleHarness
xcrun swift test
xcrun swift run GhostMediaAppleHarness
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

The macOS SwiftUI target is still an application shell. Networking, identity,
TLS, DNS-SD, Keychain, and platform audio begin in later phases. See
[ARCHITECTURE.md](ARCHITECTURE.md) for module ownership and
[INTEGRATION.md](INTEGRATION.md) for the Phase 1 contract.
