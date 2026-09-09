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

`GhostMediaRuntime` under `runtime/` is the cross-platform userspace provider used
by Windows and Apple. It owns OpenSSL 3 AES-256-GCM, Ed25519/X.509, pinned mutual
TLS 1.3, exporters, and portable socket I/O while relying on `gm_core` for wire
layout, replay, epoch, policy, and exporter-context validation. Windows protected
Production identity/trust persistence and service orchestration remain separate work.

The Windows preset uses vcpkg manifest mode through `VCPKG_ROOT`. Visual Studio's
bundled vcpkg is sufficient:

```powershell
$env:VCPKG_ROOT = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\vcpkg"
cmake --preset windows-msvc
```

Phase 2 local smoke:

```powershell
$ctest = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
& $ctest --preset windows-msvc -R '^(gm_phase2_vectors_tests|runtime_security_tests)$' --output-on-failure
```

## First Mac interop probe

`GhostMediaWinControlProbe` under `tools/control_probe/` is the Windows-side
command-line harness for first Mac communication tests. It uses `gm_core` to build
and validate control frames, then drives the initial `session.hello`,
`transport.bind`, and `stream.open` sequence. It also validates the expected
Windows-to-Apple `PATH_CHALLENGE` and Apple-to-Windows `PATH_RESPONSE` header
directions. Its TCP I/O comes from `GhostMediaRuntime`, but it does not send
encrypted UDP media yet.

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

For the secured Phase 3 synthetic-media fixture, see
[PHASE3_TEST.md](PHASE3_TEST.md). It uses `--phase3-test` to select pinned mutual
TLS, TLS-exporter keys, protected UDP path validation, and a deterministic PCM sender.
Use `--expect-server-id <uuid>` once the Mac harness has a stable test server ID so
the Windows probe rejects an unexpected peer identity during `session.hello`.
