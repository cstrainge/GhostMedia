# GhostMedia shared runtime

`GhostMediaRuntime` is the cross-platform userspace runtime consumed by Windows,
macOS, and iOS. It is separate from the deterministic `gm_core` protocol library.

The runtime owns:

- OpenSSL 3 Ed25519 keys and self-signed X.509 leaf certificates.
- Pinned, leaf-only mutual TLS 1.3 with ALPN `ghostmedia/1`.
- TLS exporter output.
- AES-256-GCM provider operations.
- Portable socket mechanics. The current implementation covers TCP; UDP will be
  added to this runtime rather than to either platform host.

Platform hosts own lifecycle, eligible-interface policy, protected identity and
trust persistence, UI, and audio-device integration. They call the C ABI in
`include/ghostmedia/gm_runtime.h`; they do not duplicate socket, TLS, certificate,
or media-cryptography implementations.

CMake resolves OpenSSL 3 through the repository vcpkg manifest. SwiftPM uses the
pinned `OpenSSL-Package` XCFramework so the same runtime sources compile for macOS
and iOS.
