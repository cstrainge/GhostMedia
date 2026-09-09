# GhostMedia repository instructions

## Build and test commands

The repository has two build graphs: CMake for the portable C++ core and Windows
userspace target, and Swift Package Manager at the repository root for Apple code.

### CMake / C++ core

Requires CMake 3.20 or newer.

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Run one registered CTest test:

```sh
ctest --preset default -R '^gm_core_tests$'
```

The shared build also registers `gm_core_c_abi_tests`,
`gm_phase2_vectors_tests`, and `runtime_security_tests`; these are custom test
executables and do not support filtering their individual test functions.

On Windows, use the checked-in MSVC preset:

```powershell
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

The Windows-only `GhostMediaStreamSvc` target is added only when configuring on
Windows with `GM_BUILD_WINDOWS=ON`.

### Swift / Apple targets

Run Swift commands from the repository root with the installed Xcode toolchain:

```sh
xcrun swift build --product GhostMediaAppleHarness
xcrun swift build --product GhostMediaMac
xcrun swift test
xcrun swift run GhostMediaAppleHarness
xcrun swift run GhostMediaRuntimeTests
xcrun swift run GhostMediaMac
```

Run one Swift Testing test by function name:

```sh
xcrun swift test --filter sharedCoreVersionIsAvailableThroughTheSwiftBridge
```

There is no standalone lint target. CMake builds enforce C++20 and compile with
`/W4 /permissive-` on MSVC or `-Wall -Wextra -Wpedantic` elsewhere.

## Architecture and source of truth

- `docs/` is the normative protocol design, currently `1.0-draft.1`; it describes
  intended behavior beyond the current scaffold. Start with `docs/README.md` and
  `docs/01-architecture.md`. Wire definitions in documents 02-04 override
  narrative examples, document 05 owns media semantics, document 06 owns the
  Windows local ABI, and document 07 is the central limits reference. Resolve
  contradictions in the specification instead of creating platform-specific
  interpretations.
- `shared/` is the portable C++20 protocol core used by both platforms. It owns
  wire parsing/serialization, validation, protocol state, timing arithmetic, and
  bounded protocol policy; it must not own sockets, TLS engines, threads, UI,
  filesystems, device APIs, or platform audio.
- `runtime/` is the cross-platform C++ userspace runtime. It owns OpenSSL
  identity/certificate operations, TLS 1.3, exporters, AES-256-GCM, and the
  currently implemented portable TCP socket mechanics. Add future UDP mechanics
  here rather than in a platform host. Platform hosts own lifecycle, interface
  policy, protected persistence, trust decisions, UI, and audio.
- `shared/include/ghostmedia/gm_core.h` is the cross-language C ABI. CMake builds
  it as `gm_core`; SwiftPM compiles the same sources as `GhostMediaCore`.
- `WinDevice/` owns Windows-only code. The current implementation is only the
  `GhostMediaStreamSvc` userspace scaffold linked to the shared core. The WaveRT
  driver and its bridge are intentionally not scaffolded yet.
- `AppleOutputServer/` is layered as:
  `GhostMediaMac` composition root -> `GhostMediaAppleUI` and
  `GhostMediaAppleCore` -> `GhostMediaProtocolBridge` -> `GhostMediaCore`.
  `GhostMediaProtocolBridge` alone wraps raw C ABI calls into safe Swift values.
  Apple core/UI code must not duplicate protocol parsing or state transitions.
- `GhostMediaAppleHarness` is the deterministic Phase 1 CLI. Keep it free of UI,
  DNS-SD, Keychain, UDP media, and audio dependencies. It may exercise the shared
  runtime TLS and TCP boundaries. Its explicit
  `--listen <port> --allow-plaintext` mode is the only Phase 1 TCP exception and
  must remain a one-shot test endpoint.
- The Windows service is the TCP control client and UDP media sender. The
  macOS/iOS app is the TCP output server and UDP media receiver. The Apple host
  plays through its local system-default output route; the protocol does not
  enumerate or select Apple-attached devices.

## Repository-specific conventions

- Keep protocol terminology platform-neutral: use `apple-output-server`,
  `win_to_apple`, and Apple output server/media receiver. Tests intentionally
  reject obsolete `mac-client`, `win_to_mac`, and `endpoint_state` spellings.
- Treat protocol schemas as closed and bounded. Reject unknown or duplicate JSON
  fields, invalid UTF-8, unsupported versions, reserved nonzero bytes, invalid
  enum values, and values beyond constants in `gm_core.h`; do not accept
  permissive platform-parser behavior.
- Wire integers are fixed-width and explicitly encoded. Control frames use a
  four-byte big-endian length prefix; GMA/1 media header fields and nonces use
  the layouts in `docs/04-media-protocol.md`. Do not serialize C/C++ structure
  memory directly.
- Every public ABI structure begins with `struct_size` and `abi_version`.
  Validate both where required, preserve the caller's `struct_size` when filling
  output structures, append new fields rather than reordering existing fields,
  use caller-owned buffers, and report required capacity with
  `GM_BUFFER_TOO_SMALL`. Never expose C++ classes, STL types, exceptions,
  templates, or compiler-specific layouts across the ABI.
- Other Swift targets import `GhostMediaProtocolBridge`, not `GhostMediaCore`.
  Keep bridge errors and values `Sendable`; Apple application contracts use
  async boundaries and `AsyncStream` snapshots. SwiftUI views consume injected
  configuration/services and must not own sockets, Keychain state, audio units,
  or protocol state.
- Real-time paths are isolation boundaries. The Windows render path must never
  wait for userspace or the network. Apple audio callbacks may only pull PCM from
  a preallocated ring and supply silence on underflow; keep allocation, locks,
  logging, networking, decrypt/decode, and resampling off the callback.
- Preserve bounded-resource and freshness behavior: queues have fixed capacity,
  stale audio is discarded rather than retransmitted, TCP controls lifecycle,
  and UDP cannot create streams or change negotiated formats.
- C++ tests use the lightweight `check`/`check_status` harness in
  `shared/tests/gm_core_tests.cpp`. Swift tests use the Swift Testing package
  (`import Testing`, `@Test`, and `#expect`), not XCTest.
- Protocol or ABI changes should update the normative document, shared header and
  implementation, negative/positive tests, and Swift bridge together. Never fix
  an interoperability mismatch only in one platform adapter.
