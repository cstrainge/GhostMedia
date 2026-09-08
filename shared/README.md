# GhostMedia Shared Core

The shared core is a portable C++20 static library with a C ABI. Platform code owns
sockets, TLS, DNS-SD, threads, clocks, device APIs, key stores, and audio codecs;
the shared core owns deterministic wire parsing and byte layout helpers.

## Apple integration surface

Swift imports the public C ABI through the Clang module map at
`shared/include/module.modulemap`:

```swift
import GhostMediaCore
```

When testing from the repository root on macOS, build the static library and run the
C/C++ smoke tests before wiring it into the Apple output server:

```sh
cmake -S . -B out/build/macos -DGM_BUILD_WINDOWS=OFF -DGM_BUILD_TESTS=ON
cmake --build out/build/macos --target gm_core gm_core_tests gm_core_c_abi_tests gm_phase2_vectors_tests
ctest --test-dir out/build/macos --output-on-failure
```

For a direct Swift CLI smoke, point Swift at the include directory and built library
directory:

```sh
swiftc -I shared/include -L out/build/macos/shared -lgm_core Sources/main.swift
```

The first Apple harness should call `gm_get_version`, feed control JSON through
`gm_control_parse_message`, and use the media header/nonce/replay helpers directly.
It should not duplicate JSON schema decisions in Swift.

## Phase 2 crypto and identity vectors

The shared C ABI now exposes the deterministic parts of the Phase 2 security
contract. Platform TLS and certificate parsing stay outside the core, but adapters
must feed their observed facts and exporter bytes through these functions:

- `gm_identity_encode_peer_id` for lowercase no-padding base32 peer IDs from the
	32-byte SPKI SHA-256 digest.
- `gm_tls_peer_policy_validate` and `gm_trust_record_authorizes` for the v1
	leaf-only mutual TLS policy observation and local trust decision.
- `gm_crypto_build_exporter_context` for the exact 32-byte SHA-256 TLS exporter
	context.
- `gm_crypto_split_exporter_output` for the 64-byte exporter output split into
	media and path keys.
- `gm_media_build_aad`, `gm_media_build_nonce`, `gm_crypto_validate_aead_inputs`,
	`gm_replay_window_accept`, and `gm_epoch_window_accept` for media packet
	admission and rekey overlap.

The machine-readable fixture corpus is in
`protocol/vectors/phase2_crypto_vectors.json`, and the portable lock test is
`gm_phase2_vectors_tests`. Any change to SPKI form, exporter context, AAD, nonce,
replay, or rekey semantics should update the fixture and this test together.