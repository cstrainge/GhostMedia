# First Integration Handoff

This handoff is for the agent building the first Mac-side integration. Keep the
first slice as a Swift command-line harness around the shared C ABI. Do not start
with UI, Core Audio, Network.framework, TLS, DNS-SD, or device routing.

## Shared Core Contract

The shared core is the source of truth for deterministic protocol parsing and byte
layout helpers. The Mac side should import it through the Clang module map:

```swift
import GhostMediaCore
```

Repository paths:

- `shared/include/ghostmedia/gm_core.h`: public C ABI.
- `shared/include/module.modulemap`: Swift/Clang module definition.
- `shared/README.md`: build and import notes.
- `shared/tests/gm_core_c_abi_tests.c`: C ABI smoke coverage.

The Mac harness should call the C ABI directly for:

- `gm_get_version` startup verification.
- `gm_control_parse_message` for all v1 control JSON fixtures.
- `gm_control_encode_frame` and `gm_control_peek_frame` for TCP framing tests.
- `gm_media_encode_header`, `gm_media_decode_header`, and `gm_media_build_nonce`
  for media byte-layout tests.
- `gm_replay_window_init` and `gm_replay_window_accept` for replay-window checks.

Do not duplicate the v1 JSON schema in Swift. Swift can translate parsed ABI fields
into local types after the shared core accepts a message.

## Build Smoke

From the repository root on macOS:

```sh
cmake -S . -B out/build/macos -DGM_BUILD_WINDOWS=OFF -DGM_BUILD_TESTS=ON
cmake --build out/build/macos --target gm_core gm_core_tests gm_core_c_abi_tests
ctest --test-dir out/build/macos --output-on-failure
```

For a tiny Swift import check, compile a CLI against the include and library output
directories:

```sh
swiftc -I shared/include -L out/build/macos/shared -lgm_core Sources/main.swift
```

The first Swift smoke should fail fast unless `gm_get_version` reports
`GM_ABI_VERSION == 1` and `GM_PROTOCOL_MAJOR == 1`.

## First Harness Scope

Implement a CLI receiver harness with deterministic inputs and printed JSON or text
results. The initial run should prove:

- The Swift compiler can import `GhostMediaCore` without private headers.
- `session.hello` with `role:"win-client"` parses and `role:"mac-client"` is
  rejected.
- `stream.open` with `direction:"win_to_apple"` parses and `win_to_mac` is rejected.
- `stream.start` requires `first_media_timestamp` and exposes the parsed decimal
  string.
- A `session.hello` result accepts `role:"apple-output-server"`, `server_id`,
  `boot_id`, `session_id`, `capabilities`, and `limits`.
- `event.output.state` parses and removed path-validation control events are
  rejected.
- A Windows-to-Apple `PATH_CHALLENGE` header and Apple-to-Windows `PATH_RESPONSE`
  header encode with directions 1 and 2 respectively.

## Non-Goals For This Slice

- No real sockets, TLS, mDNS, Keychain, Core Audio, AVFoundation, or UI.
- No platform JSON parser for protocol acceptance decisions.
- No AES-GCM implementation until the Phase 2 vector lock.
- No output device enumeration; v1 uses only the local system-default output route.

## Handshake Shape

Use this trace as the fixture spine:

```text
Win -> Apple  session.hello(role=win-client, udp_port=49152)
Apple -> Win  result(role=apple-output-server, server_id, session_id, udp_port)
Win -> Apple  transport.bind(session_id, udp_port=49152)
Apple -> Win  result(path_state=bound)
Win -> Apple  stream.open(direction=win_to_apple, PCM 48k/stereo/240)
Apple -> Win  result(stream_id=1, key_epoch=1, path_state=probing)
Win => Apple  GMA PATH_CHALLENGE direction=WIN_TO_APPLE
Apple => Win  GMA PATH_RESPONSE direction=APPLE_TO_WIN
Win -> Apple  stream.start(stream_id=1, first_media_timestamp="...")
Apple -> Win  result(state=started)
```

Any Mac-side fixture that accepts the old `mac-client`, `win_to_mac`,
`event.path.validated`, or `source_media_timestamp` assumptions is stale.