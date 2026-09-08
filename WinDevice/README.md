# WinDevice

Windows implementation home: persistent virtual audio driver, user-mode streaming
service, and Windows configuration support. No implementation is included yet.

Start with the [protocol design](../docs/README.md) and the
[driver/service boundary](../docs/06-windows-driver-boundary.md).

## Current scaffold

The initial Windows userspace target is `GhostMediaStreamSvc` under `service/`.
It links the shared `gm_core` static library and currently acts as a console
starter for the future service host. The WaveRT driver project is intentionally
not scaffolded yet; the protocol core and userspace vertical slice should build
and pass tests before WDK driver work begins.

`GhostMediaWinSecurity` under `security/` is the first Windows-side Phase 2
adapter. It uses Windows BCrypt for AES-256-GCM and relies on the shared core for
key, nonce, AAD, payload, tag, replay, and epoch validation. It does not implement
the v1 Ed25519 TLS identity adapter yet; the installed Windows SDK headers in this
environment do not expose CNG/NCrypt Ed25519 constants, so that adapter needs an
external TLS/crypto provider choice or newer platform support.

Phase 2 local smoke:

```powershell
$ctest = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
& $ctest --preset windows-msvc -R '^(gm_phase2_vectors_tests|win_crypto_provider_tests)$' --output-on-failure
```

## First Mac interop probe

`GhostMediaWinControlProbe` under `tools/control_probe/` is the Windows-side
command-line harness for first Mac communication tests. It uses `gm_core` to build
and validate control frames, then drives the initial `session.hello`,
`transport.bind`, and `stream.open` sequence. It also validates the expected
Windows-to-Apple `PATH_CHALLENGE` and Apple-to-Windows `PATH_RESPONSE` header
directions, but it does not send encrypted UDP media yet.

Local dry-run:

```powershell
.\out\build\windows-msvc\WinDevice\tools\control_probe\Debug\GhostMediaWinControlProbe.exe --dry-run
```

Pre-TLS framed TCP test against a Mac CLI harness:

```powershell
.\out\build\windows-msvc\WinDevice\tools\control_probe\Debug\GhostMediaWinControlProbe.exe --connect <mac-host> <port> --allow-plaintext
```

The `--allow-plaintext` flag is deliberate. This probe is for first interop only;
the v1 protocol still requires mutually pinned TLS before real conformance testing.
Use `--expect-server-id <uuid>` once the Mac harness has a stable test server ID so
the Windows probe rejects an unexpected peer identity during `session.hello`.
